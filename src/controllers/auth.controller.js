'use strict';

/**
 * Controlador de autenticación WebAuthn/FIDO2.
 *
 * FLUJO CRIPTOGRÁFICO (resumen para la memoria del proyecto):
 *
 * REGISTRO (attestation):
 *  1. El servidor genera un Reto Criptográfico (challenge) de un solo uso y
 *     lo guarda con TTL. Incluye rpId, user.id, algoritmos y excludeCredentials.
 *  2. El navegador llama a navigator.credentials.create(). El autenticador
 *     (Windows Hello/TPM 2.0 o una llave USB como YubiKey) crea un par de
 *     claves: la PRIVADA nunca sale del dispositivo; la PÚBLICA se devuelve
 *     firmada junto con la attestation.
 *  3. El servidor verifica challenge, origin, rpId y la attestation, y guarda
 *     la llave pública + counter en `credenciales_webauthn`.
 *
 * LOGIN (assertion):
 *  1. El servidor genera un nuevo challenge + allowCredentials y lo guarda
 *     con TTL de un solo uso.
 *  2. El autenticador firma el challenge con la llave privada.
 *  3. El servidor verifica la firma con la llave pública, valida
 *     challenge/origin/rpId y que el counter haya aumentado (anti-clonación).
 *  4. Si verifica, actualiza el counter y emite un JWT con claim `jti`
 *     (= id_sesion). La sesión se registra en `sesiones_iam`.
 */

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const crypto = require('crypto');

const db = require('../config/db');
const config = require('../config/env');
const { ChallengeStore } = require('../utils/challengeStore');
const {
  signSessionToken,
  verifySessionToken,
  verifySessionTokenIgnoringExpiration,
} = require('../services/tokenService');

// Roles válidos del Empleado (Tabla 1 del documento de tesis).
const ROLES_VALIDOS = ['usuario', 'admin', 'operativo', 'gerencia'];

const EMAIL_MAX = 254;
const NOMBRE_MAX = 255;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Retos de un solo uso con TTL y cota de memoria (antes eran Map eternos).
const registrationChallenges = new ChallengeStore({
  ttlMs: config.challengeTtlMs,
  maxEntries: config.maxChallenges,
});
const authenticationChallenges = new ChallengeStore({
  ttlMs: config.challengeTtlMs,
  maxEntries: config.maxChallenges,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizarEmail(value) {
  return String(value ?? '').trim().toLowerCase();
}

function emailValido(email) {
  return email.length > 0 && email.length <= EMAIL_MAX && EMAIL_RE.test(email);
}

function normalizarNombre(value, fallback) {
  const nombre = String(value ?? '').trim().replace(/\s+/g, ' ');
  if (!nombre) return fallback;
  return nombre.length <= NOMBRE_MAX ? nombre : null;
}

function parseRol(value) {
  const rol = String(value ?? '').trim().toLowerCase();
  if (!rol) return 'usuario';
  return ROLES_VALIDOS.includes(rol) ? rol : null;
}

function publicUser(user) {
  return {
    id_usuario: user.id_usuario,
    email: user.email,
    nombre_completo: user.nombre_completo,
    rol: user.rol,
    estado: user.estado,
  };
}

function errorPublico(err) {
  if (config.isProduction) return 'La operación WebAuthn no pudo completarse';
  return err?.message || 'La operación WebAuthn no pudo completarse';
}

function extractToken(req) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return (
    (match ? match[1].trim() : null) ||
    req.cookies?.[config.sessionCookieName] ||
    (typeof req.body?.token === 'string' ? req.body.token : null)
  );
}

function logError(tag, req, err) {
  console.error(`[${tag}][${req.id || '-'}]`, err);
}

/** Un rechazo esperado de WebAuthn no debe llenar el log con stack traces. */
function logRejection(tag, req, err) {
  if (config.nodeEnv === 'test') return;
  console.warn(`[${tag}][${req.id || '-'}] ${err.message}`);
}

/** Errores de node-postgres traen un SQLSTATE de 5 caracteres. */
function isDatabaseError(err) {
  return Boolean(err && typeof err.code === 'string' && /^[0-9A-Z]{5}$/.test(err.code));
}

async function findUserByEmail(email) {
  const { rows } = await db.query('SELECT * FROM usuarios WHERE email = $1', [email]);
  return rows[0];
}

async function findCredentialsByUserId(idUsuario) {
  const { rows } = await db.query(
    'SELECT * FROM credenciales_webauthn WHERE id_usuario = $1',
    [idUsuario]
  );
  return rows;
}

/**
 * Devuelve el usuario dueño de la sesión del request, consultando el rol
 * actual en PostgreSQL (no el rol congelado en el JWT). Así una degradación
 * de privilegios se aplica de inmediato.
 */
async function authenticatedUserFromRequest(req) {
  const token = extractToken(req);
  if (!token) return null;

  try {
    const payload = verifySessionToken(token);
    if (!payload.jti || !payload.id_usuario) return null;

    const { rows } = await db.query(
      `SELECT u.id_usuario, u.rol
         FROM sesiones_iam s
         JOIN usuarios u ON u.id_usuario = s.id_usuario
        WHERE s.id_sesion = $1
          AND s.id_usuario = $2
          AND s.fecha_expiracion > NOW()
          AND u.estado = TRUE`,
      [payload.jti, payload.id_usuario]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

async function requesterIsAdmin(req) {
  const user = await authenticatedUserFromRequest(req);
  return user?.rol === 'admin';
}

async function requesterIsUser(req, idUsuario) {
  const user = await authenticatedUserFromRequest(req);
  return Boolean(user && user.id_usuario === idUsuario);
}

/**
 * Política de asignación de roles.
 * - `usuario` siempre se puede asignar.
 * - En modo demo (`ALLOW_PUBLIC_ROLE_SELECTION=true`) se permite elegir rol.
 * - En modo seguro, solo un admin autenticado o el primer usuario (bootstrap).
 */
async function canAssignRole(req, rol) {
  if (rol === 'usuario') return true;
  if (config.allowPublicRoleSelection) return true;

  const { rows } = await db.query('SELECT 1 FROM usuarios LIMIT 1');
  if (rows.length === 0) return true; // alta del primer administrador

  return requesterIsAdmin(req);
}

// ---------------------------------------------------------------------------
// REGISTRO
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/register-challenge
 * Body: { email, nombre_completo, rol }
 * Retorna PublicKeyCredentialCreationOptionsJSON.
 */
async function registerChallenge(req, res) {
  try {
    const email = normalizarEmail(req.body?.email);
    if (!emailValido(email)) {
      return res.status(400).json({ error: 'Email inválido' });
    }

    const nombreSolicitado = normalizarNombre(req.body?.nombre_completo, '');
    if (nombreSolicitado === null) {
      return res.status(400).json({
        error: `nombre_completo no puede superar ${NOMBRE_MAX} caracteres`,
      });
    }

    const rol = parseRol(req.body?.rol);
    if (!rol) {
      return res.status(400).json({
        error: `Rol inválido. Valores permitidos: ${ROLES_VALIDOS.join(', ')}`,
      });
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser && !existingUser.estado) {
      return res.status(403).json({ error: 'Usuario deshabilitado' });
    }

    // Política de alta:
    //  - Usuario NUEVO: alta pública (sujeta a la política de roles).
    //  - Usuario EXISTENTE: solo puede añadir otra passkey si ya inició sesión
    //    con esa misma cuenta, o si lo hace un administrador. Sin esto,
    //    cualquiera podría registrar su propio autenticador en la cuenta de
    //    otra persona conociendo su email (account takeover).
    let rolFinal = rol;
    if (existingUser) {
      const isSelf = await requesterIsUser(req, existingUser.id_usuario);
      if (!isSelf) {
        const isAdmin = await requesterIsAdmin(req);
        if (!isAdmin) {
          return res.status(403).json({
            error:
              'Para añadir una llave a una cuenta existente debes iniciar sesión con esa cuenta o ser administrador',
          });
        }
      }
      // El enrolamiento de una llave NO cambia el rol: un cambio de rol debe
      // ser una acción administrativa explícita y auditada, no un efecto
      // colateral del formulario de alta.
      rolFinal = existingUser.rol;
    } else if (!(await canAssignRole(req, rol))) {
      return res.status(403).json({
        error: 'Solo un administrador autenticado puede asignar ese rol',
      });
    }

    const nombreFinal = nombreSolicitado || existingUser?.nombre_completo || email;

    const existingCreds = existingUser
      ? await findCredentialsByUserId(existingUser.id_usuario)
      : [];

    // user.id estable: el UUID real de la BD para usuarios existentes o uno
    // nuevo que se persistirá tal cual en register-verify.
    const userId = existingUser?.id_usuario || crypto.randomUUID();

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpId,
      userName: email,
      userDisplayName: nombreFinal,
      userID: Buffer.from(userId, 'utf8'),
      attestationType: 'none',
      excludeCredentials: existingCreds.map((c) => ({ id: c.id_credencial })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        // Se omite `authenticatorAttachment` a propósito: así se aceptan
        // autenticadores de plataforma (TPM 2.0 / Windows Hello / Touch ID)
        // y roaming/cross-platform (YubiKey), alineado con la Tabla 2.
      },
    });

    registrationChallenges.set(email, {
      challenge: options.challenge,
      email,
      nombre: nombreFinal,
      rol: rolFinal,
      userId,
    });

    return res.json(options);
  } catch (err) {
    logError('register-challenge', req, err);
    return res.status(500).json({
      error: 'No se pudo generar el reto de registro',
      request_id: req.id,
    });
  }
}

/**
 * POST /api/auth/register-verify
 * Body: { email, attResp }
 * Verifica la attestation y persiste usuario + llave pública.
 *
 * El rol y el nombre se toman del reto guardado en el servidor, no del body,
 * para impedir que el cliente los altere entre ambas peticiones.
 */
async function registerVerify(req, res) {
  try {
    const email = normalizarEmail(req.body?.email);
    const attResp = req.body?.attResp;

    if (!emailValido(email) || !attResp) {
      return res.status(400).json({
        verified: false,
        error: 'email y attResp son requeridos',
      });
    }

    const stored = registrationChallenges.consume(email);
    if (!stored) {
      return res.status(400).json({
        verified: false,
        error: 'Reto de registro expirado o ya utilizado. Solicita uno nuevo.',
      });
    }

    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: stored.challenge,
      expectedOrigin: config.origins,
      expectedRPID: config.rpId,
      // Las opciones usan userVerification: 'preferred'; no exigimos UV para
      // no rechazar llaves USB sin PIN configurado.
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({
        verified: false,
        error: 'La attestation no verificó',
      });
    }

    const { registrationInfo } = verification;
    const credential = registrationInfo.credential;
    const credentialID = credential.id;
    const publicKeyB64 = isoBase64URL.fromBuffer(Buffer.from(credential.publicKey));
    const counter = Number(credential.counter) || 0;

    // Una credencial no puede quedar vinculada a dos identidades.
    const { rows: ownerRows } = await db.query(
      'SELECT id_usuario FROM credenciales_webauthn WHERE id_credencial = $1',
      [credentialID]
    );
    if (ownerRows.length > 0 && ownerRows[0].id_usuario !== stored.userId) {
      return res.status(409).json({
        verified: false,
        error: 'Esa credencial ya está registrada en otra cuenta',
      });
    }

    // Alta sin efectos colaterales: si el email ya existe, NO se actualiza el
    // rol desde el reto (evita carreras de privilegios). Solo se actualiza el
    // nombre, y únicamente si el id coincide con el usuario autorizado.
    const { rows: insertedRows } = await db.query(
      `INSERT INTO usuarios (id_usuario, email, nombre_completo, rol, estado)
       VALUES ($1, $2, $3, $4, TRUE)
       ON CONFLICT (email) DO NOTHING
       RETURNING *`,
      [stored.userId, stored.email, stored.nombre, stored.rol]
    );

    let user = insertedRows[0];
    if (!user) {
      const { rows } = await db.query('SELECT * FROM usuarios WHERE email = $1', [
        stored.email,
      ]);
      user = rows[0];

      if (!user || user.id_usuario !== stored.userId) {
        return res.status(409).json({
          verified: false,
          error: 'La cuenta cambió durante el registro. Solicita un nuevo reto.',
        });
      }

      if (!user.estado) {
        return res.status(403).json({ verified: false, error: 'Usuario deshabilitado' });
      }

      const { rows: updatedRows } = await db.query(
        'UPDATE usuarios SET nombre_completo = $1 WHERE id_usuario = $2 RETURNING *',
        [stored.nombre, user.id_usuario]
      );
      user = updatedRows[0];
    }

    await db.query(
      `INSERT INTO credenciales_webauthn
         (id_credencial, id_usuario, llave_publica, contador_firmas, tipo_autenticador)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id_credencial) DO UPDATE
         SET contador_firmas   = EXCLUDED.contador_firmas,
             tipo_autenticador = EXCLUDED.tipo_autenticador
       WHERE credenciales_webauthn.id_usuario = EXCLUDED.id_usuario`,
      [
        credentialID,
        user.id_usuario,
        publicKeyB64,
        counter,
        attResp.authenticatorAttachment || 'desconocido',
      ]
    );

    return res.json({ verified: true, user: publicUser(user) });
  } catch (err) {
    if (isDatabaseError(err)) {
      logError('register-verify', req, err);
      return res.status(500).json({
        verified: false,
        error: 'No se pudo guardar la credencial en PostgreSQL',
        request_id: req.id,
      });
    }
    logRejection('register-verify', req, err);
    return res.status(400).json({ verified: false, error: errorPublico(err) });
  }
}

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/login-challenge
 * Body: { email }
 * Retorna PublicKeyCredentialRequestOptionsJSON.
 */
async function loginChallenge(req, res) {
  try {
    const email = normalizarEmail(req.body?.email);
    if (!emailValido(email)) {
      return res.status(400).json({ error: 'Email inválido' });
    }

    const user = await findUserByEmail(email);
    const creds = user && user.estado
      ? await findCredentialsByUserId(user.id_usuario)
      : [];

    // Respuesta genérica: no revela si el email existe, está deshabilitado
    // o simplemente no tiene passkeys (mitiga enumeración de usuarios).
    if (!user || !user.estado || creds.length === 0) {
      return res.status(404).json({
        error: 'No hay credenciales disponibles para ese identificador',
      });
    }

    const options = await generateAuthenticationOptions({
      rpID: config.rpId,
      allowCredentials: creds.map((c) => ({ id: c.id_credencial })),
      userVerification: 'preferred',
    });

    authenticationChallenges.set(email, {
      challenge: options.challenge,
      userId: user.id_usuario,
    });

    return res.json(options);
  } catch (err) {
    logError('login-challenge', req, err);
    return res.status(500).json({
      error: 'No se pudo generar el reto de login',
      request_id: req.id,
    });
  }
}

/**
 * POST /api/auth/login-verify
 * Body: { email, asseResp }
 * Verifica la firma, actualiza el counter anti-clonación y emite un JWT.
 */
async function loginVerify(req, res) {
  try {
    const email = normalizarEmail(req.body?.email);
    const asseResp = req.body?.asseResp;

    if (!emailValido(email) || !asseResp) {
      return res.status(400).json({
        verified: false,
        error: 'email y asseResp son requeridos',
      });
    }

    const stored = authenticationChallenges.consume(email);
    if (!stored) {
      return res.status(400).json({
        verified: false,
        error: 'Reto de login expirado o ya utilizado. Solicita uno nuevo.',
      });
    }

    const user = await findUserByEmail(email);
    if (!user || !user.estado || user.id_usuario !== stored.userId) {
      return res.status(401).json({ verified: false, error: 'Autenticación rechazada' });
    }

    const creds = await findCredentialsByUserId(user.id_usuario);
    const storedCred = creds.find((c) => c.id_credencial === asseResp.id);
    if (!storedCred) {
      return res.status(401).json({ verified: false, error: 'Autenticación rechazada' });
    }

    const verification = await verifyAuthenticationResponse({
      response: asseResp,
      expectedChallenge: stored.challenge,
      expectedOrigin: config.origins,
      expectedRPID: config.rpId,
      credential: {
        id: storedCred.id_credencial,
        publicKey: isoBase64URL.toBuffer(storedCred.llave_publica),
        counter: Number(storedCred.contador_firmas),
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(401).json({ verified: false, error: 'Firma digital FIDO2 inválida' });
    }

    // Anti-clonación: el autenticador incrementa su contador en cada uso.
    const newCounter = verification.authenticationInfo.newCounter;
    await db.query(
      'UPDATE credenciales_webauthn SET contador_firmas = $1 WHERE id_credencial = $2',
      [newCounter, storedCred.id_credencial]
    );

    // Emisión del Token JWT de Acceso Unificado y registro de la sesión.
    const idSesion = crypto.randomUUID();
    const token = signSessionToken(user, idSesion);
    const fechaExpiracion = new Date(Date.now() + config.sessionTtlMs);

    // Higiene: elimina sesiones vencidas del mismo usuario.
    await db.query(
      'DELETE FROM sesiones_iam WHERE id_usuario = $1 AND fecha_expiracion <= NOW()',
      [user.id_usuario]
    );

    await db.query(
      `INSERT INTO sesiones_iam (id_sesion, id_usuario, token_jwt, fecha_expiracion)
       VALUES ($1, $2, $3, $4)`,
      [idSesion, user.id_usuario, token, fechaExpiracion]
    );

    res.cookie(config.sessionCookieName, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.cookieSecure,
      path: '/',
      maxAge: config.sessionTtlMs,
    });

    return res.json({
      verified: true,
      token,
      id_sesion: idSesion,
      expires_in: Math.floor(config.sessionTtlMs / 1000),
      user: publicUser(user),
    });
  } catch (err) {
    if (isDatabaseError(err)) {
      logError('login-verify', req, err);
      return res.status(500).json({
        verified: false,
        error: 'No se pudo completar la autenticación en PostgreSQL',
        request_id: req.id,
      });
    }
    logRejection('login-verify', req, err);
    return res.status(401).json({
      verified: false,
      error: 'La firma digital FIDO2 no es válida o el reto expiró',
    });
  }
}

/**
 * POST /api/auth/logout
 * Invalida la sesión en PostgreSQL y limpia la cookie httpOnly.
 * Acepta el token vía Authorization: Bearer, cookie o body { token }.
 */
async function logout(req, res) {
  const token = extractToken(req);
  let revoked = true;

  try {
    if (token) {
      let payload;
      try {
        // Firma válida incluso si el token ya expiró: así se puede revocar
        // una sesión caducada sin aceptar un jti falsificado.
        payload = verifySessionTokenIgnoringExpiration(token);
      } catch {
        payload = null;
      }

      if (payload?.jti) {
        await db.query('DELETE FROM sesiones_iam WHERE id_sesion = $1', [payload.jti]);
      } else {
        // Compatibilidad con tokens antiguos sin claim jti.
        await db.query('DELETE FROM sesiones_iam WHERE token_jwt = $1', [token]);
      }
    }
  } catch (err) {
    revoked = false;
    logError('logout', req, err);
  }

  res.clearCookie(config.sessionCookieName, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.cookieSecure,
    path: '/',
  });

  if (!revoked) {
    return res.status(500).json({
      error: 'No se pudo revocar la sesión en PostgreSQL',
      request_id: req.id,
    });
  }

  return res.json({ ok: true, message: 'Sesión IAM cerrada correctamente' });
}

module.exports = {
  registerChallenge,
  registerVerify,
  loginChallenge,
  loginVerify,
  logout,
  // Expuesto solo para pruebas automatizadas y limpieza entre casos.
  __stores: { registrationChallenges, authenticationChallenges },
};
