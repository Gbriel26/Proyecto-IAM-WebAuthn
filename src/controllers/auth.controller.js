/**
 * Controlador de autenticación WebAuthn/FIDO2.
 *
 * FLUJO CRIPTOGRÁFICO (resumen para la memoria del proyecto):
 *
 * REGISTRO (attestation):
 *  1. Servidor genera un `challenge` aleatorio (32+ bytes) + opciones
 *     (rpId, rpName, user.id, algoritmos). Lo guarda temporalmente.
 *  2. El navegador llama a navigator.credentials.create() (vía
 *     @simplewebauthn/browser). El autenticador (Windows Hello, Touch ID,
 *     llave USB) genera un par de claves: la PRIVADA nunca sale del
 *     dispositivo; la PÚBLICA + attestation se devuelven firmadas.
 *  3. Servidor verifica con verifyRegistrationResponse(): comprueba que el
 *     challenge devuelto sea el emitido, que el origin y rpId coincidan
 *     (anti-phishing), y valida la firma/cadena de attestation.
 *  4. Si verifica, se guarda la llave pública + counter en
 *     credenciales_webauthn. Esa llave servirá para verificar logins futuros.
 *
 * LOGIN (assertion):
 *  1. Servidor genera un nuevo `challenge` + allowCredentials (IDs de las
 *     passkeys del usuario). Lo guarda temporalmente.
 *  2. El autenticador firma el challenge con la llave PRIVADA y devuelve
 *     la assertion (authenticatorData, clientDataJSON, signature, counter).
 *  3. Servidor verifica con verifyAuthenticationResponse() usando la llave
 *     PÚBLICA almacenada: valida la firma, el challenge, origin/rpId y que
 *     el `counter` haya aumentado (anti-clonación: si el counter no avanza
 *     o retrocede, la credencial podría estar clonada).
 *  4. Si verifica, se actualiza el counter y se emite un JWT de sesión IAM
 *     que se guarda en sesiones_iam y se envía como cookie httpOnly.
 */

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../config/db');

const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'IAM Universidad';
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// Roles válidos del Empleado (Tabla 1 del documento de tesis).
const ROLES_VALIDOS = ['usuario', 'admin', 'operativo', 'gerencia'];

/** Normaliza el rol recibido; por defecto 'usuario'. */
function normalizarRol(rol) {
  const r = String(rol || 'usuario').trim().toLowerCase();
  return ROLES_VALIDOS.includes(r) ? r : 'usuario';
}

// Almacenes temporales de challenges en memoria.
// En producción usar Redis con TTL (5 min). Para la demo universitaria
// un Map es suficiente. Clave: email del usuario.
const registrationChallenges = new Map(); // email -> challenge (string)
const authenticationChallenges = new Map(); // email -> challenge (string)

/** Busca usuario por email. Retorna fila de `usuarios` o undefined. */
async function findUserByEmail(email) {
  const { rows } = await db.query('SELECT * FROM usuarios WHERE email = $1', [email]);
  return rows[0];
}

/** Lista las credenciales WebAuthn de un usuario. */
async function findCredentialsByUserId(idUsuario) {
  const { rows } = await db.query(
    'SELECT * FROM credenciales_webauthn WHERE id_usuario = $1',
    [idUsuario]
  );
  return rows;
}

// ---------------------------------------------------------------------------
// REGISTRO
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/register-challenge
 * Body: { email, nombre_completo, rol }
 * Retorna las opciones de creación (PublicKeyCredentialCreationOptionsJSON).
 */
async function registerChallenge(req, res) {
  try {
    const { email, nombre_completo, rol } = req.body;
    if (!email) return res.status(400).json({ error: 'email es requerido' });
    const rolNormalizado = normalizarRol(rol);

    const existingUser = await findUserByEmail(email);
    const existingCreds = existingUser
      ? await findCredentialsByUserId(existing_user_safe(existingUser))
      : [];

    // userID debe ser estable y opaco (bytes). Usamos el UUID existente
    // o uno pseudoaleatorio para usuarios nuevos; al verificar se crea el
    // usuario real. SimpleWebAuthn espera un Uint8Array o string.
    const userIdBytes = isoBase64URL.toBuffer(
      Buffer.from(existingUser?.id_usuario || crypto.randomUUID()).toString('base64url')
    );

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: email,
      userDisplayName: nombre_completo || email,
      userID: userIdBytes,
      attestationType: 'none', // 'none' = privacidad + demo simple (sin cert. del fabricante)
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred', // biometría/PIN si está disponible
        authenticatorAttachment: 'platform', // 'platform' (Hello/TouchID) o 'cross-platform' (llave USB). Omitir para aceptar ambas.
      },
      // Evita registrar dos veces el mismo autenticador:
      excludeCredentials: existingCreds.map((c) => ({
        id: c.id_credencial,
        type: 'public-key',
      })),
    });

    registrationChallenges.set(email, { challenge: options.challenge, rol: rolNormalizado });

    return res.json(options);
  } catch (err) {
    console.error('[register-challenge]', err);
    return res.status(500).json({ error: 'No se pudo generar el reto de registro' });
  }
}

/**
 * POST /api/auth/register-verify
 * Body: { email, nombre_completo, rol, attResp }
 *  - attResp es la respuesta del navegador (startRegistration()).
 * Verifica la attestation y persiste usuario + llave pública.
 */
async function registerVerify(req, res) {
  try {
    const { email, nombre_completo, rol, attResp } = req.body;
    if (!email || !attResp) {
      return res.status(400).json({ error: 'email y attResp son requeridos' });
    }

    const storedChallenge = registrationChallenges.get(email);
    // Compatibilidad: antes se guardaba el string plano, ahora un objeto { challenge, rol }.
    const expectedChallenge = typeof storedChallenge === 'string'
      ? storedChallenge
      : storedChallenge?.challenge;
    const rolNormalizado = normalizarRol(rol || storedChallenge?.rol);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Reto expirado o inexistente. Pide uno nuevo.' });
    }

    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return res.status(400).json({ verified: false, error: 'La attestation no verificó' });
    }

    // Compatibilidad v11/v12 (campos planos) y v13+ (registrationInfo.credential)
    const info = verification.registrationInfo || verification;
    const credential = info.credential || info;
    const credentialID = credential.id || info.credentialID;
    const credentialPublicKey = credential.publicKey || info.credentialPublicKey;
    const counter = credential.counter ?? info.counter ?? 0;

    const publicKeyB64 = isoBase64URL.fromBuffer(Buffer.from(credentialPublicKey));

    // Crea el usuario si es nuevo con su Rol de Empleado (Tabla 1).
    // Si ya existe, actualiza nombre y rol para reflejar el alta más reciente.
    let user = await findUserByEmail(email);
    if (!user) {
      const { rows } = await db.query(
        `INSERT INTO usuarios (email, nombre_completo, rol, estado)
         VALUES ($1, $2, $3, TRUE) RETURNING *`,
        [email, nombre_completo || email, rolNormalizado]
      );
      user = rows[0];
    } else {
      const { rows } = await db.query(
        `UPDATE usuarios SET nombre_completo = $1, rol = $2 WHERE id_usuario = $3 RETURNING *`,
        [nombre_completo || user.nombre_completo, rolNormalizado, user.id_usuario]
      );
      user = rows[0];
    }

    // Guarda la credencial (idempotente: si se re-registra, actualiza)
    await db.query(
      `INSERT INTO credenciales_webauthn
         (id_credencial, id_usuario, llave_publica, contador_firmas, tipo_autenticador)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id_credencial) DO UPDATE SET
         contador_firmas = EXCLUDED.contador_firmas,
         tipo_autenticador = EXCLUDED.tipo_autenticador`,
      [
        credentialID,
        user.id_usuario,
        publicKeyB64,
        counter,
        attResp.authenticatorAttachment || 'unknown',
      ]
    );

    registrationChallenges.delete(email);

    return res.json({ verified: true, user });
  } catch (err) {
    console.error('[register-verify]', err);
    return res.status(400).json({ verified: false, error: err.message });
  }
}

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/login-challenge
 * Body: { email }
 * Retorna las opciones de autenticación (PublicKeyCredentialRequestOptionsJSON).
 */
async function loginChallenge(req, res) {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email es requerido' });

    const user = await findUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'Usuario no registrado' });
    if (!user.estado) return res.status(403).json({ error: 'Usuario deshabilitado' });

    const creds = await findCredentialsByUserId(user.id_usuario);
    if (creds.length === 0) {
      return res.status(404).json({ error: 'El usuario no tiene passkeys registradas' });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      // Solo ofrece las passkeys de este usuario (flujo con identificador).
      allowCredentials: creds.map((c) => ({
        id: c.id_credencial,
        type: 'public-key',
      })),
      userVerification: 'preferred',
    });

    authenticationChallenges.set(email, options.challenge);

    return res.json(options);
  } catch (err) {
    console.error('[login-challenge]', err);
    return res.status(500).json({ error: 'No se pudo generar el reto de login' });
  }
}

/**
 * POST /api/auth/login-verify
 * Body: { email, asseResp }
 *  - asseResp es la respuesta del navegador (startAuthentication()).
 * Verifica la firma, actualiza el counter anti-clonación y emite un JWT.
 */
async function loginVerify(req, res) {
  try {
    const { email, asseResp } = req.body;
    if (!email || !asseResp) {
      return res.status(400).json({ error: 'email y asseResp son requeridos' });
    }

    const expectedChallenge = authenticationChallenges.get(email);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Reto expirado o inexistente. Pide uno nuevo.' });
    }

    const user = await findUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'Usuario no registrado' });

    const creds = await findCredentialsByUserId(user.id_usuario);
    const stored = creds.find((c) => c.id_credencial === asseResp.id);
    if (!stored) {
      return res.status(400).json({ verified: false, error: 'Credencial desconocida' });
    }

    const verification = await verifyAuthenticationResponse({
      response: asseResp,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: stored.id_credencial,
        publicKey: isoBase64URL.toBuffer(stored.llave_publica),
        counter: stored.contador_firmas,
      },
    });

    if (!verification.verified) {
      return res.status(401).json({ verified: false, error: 'Firma inválida' });
    }

    // Anti-clonación: el autenticador incrementa su contador en cada uso.
    const newCounter =
      verification.authenticationInfo?.newCounter ?? asseResp.response?.counter ?? stored.contador_firmas;
    await db.query(
      'UPDATE credenciales_webauthn SET contador_firmas = $1 WHERE id_credencial = $2',
      [newCounter, stored.id_credencial]
    );

    // Emite el Token JWT de Acceso Unificado (1 hora) y registra la
    // sesión en PostgreSQL (Tabla 3: sesiones_iam con id_sesion UUID,
    // id_usuario, token_jwt y fecha_expiracion).
    const token = jwt.sign(
      { id_usuario: user.id_usuario, email: user.email, rol: user.rol },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    const fechaExpiracion = new Date(Date.now() + 60 * 60 * 1000);
    const idSesion = crypto.randomUUID();
    // Se guarda fecha_expiracion en UTC (muro UTC sin zona) porque la columna
    // es `timestamp without time zone` y Postgres ignora el offset que envía
    // el driver (p. ej. '-05:00'). Así el valor almacenado coincide con el
    // reloj de la BD cuando esta opera en GMT/UTC.
    const fechaExpiracionUTC = fechaExpiracion.toISOString().slice(0, 19).replace('T', ' ');
    await db.query(
      'INSERT INTO sesiones_iam (id_sesion, id_usuario, token_jwt, fecha_expiracion) VALUES ($1, $2, $3, $4)',
      [idSesion, user.id_usuario, token, fechaExpiracionUTC]
    );

    authenticationChallenges.delete(email);

    // Cookie httpOnly para el frontend demo (además de devolver el token)
    res.cookie('iam_token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000,
    });

    return res.json({ verified: true, token, id_sesion: idSesion, user });
  } catch (err) {
    console.error('[login-verify]', err);
    return res.status(400).json({ verified: false, error: err.message });
  }
}

/**
 * POST /api/auth/logout
 * Invalida la sesión: elimina el Token JWT de Acceso Unificado de
 * `sesiones_iam` y limpia la cookie httpOnly. Acepta el token vía
 * `Authorization: Bearer <token>` o en el body { token }.
 */
async function logout(req, res) {
  try {
    const match = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    const bearer = match ? match[1].trim() : null;
    const token = bearer || req.body?.token || req.cookies?.iam_token || null;

    if (token) {
      await db.query('DELETE FROM sesiones_iam WHERE token_jwt = $1', [token]);
    }
    res.clearCookie('iam_token');
    return res.json({ ok: true, message: 'Sesión IAM cerrada correctamente' });
  } catch (err) {
    console.error('[logout]', err);
    return res.status(500).json({ error: 'No se pudo cerrar la sesión' });
  }
}

// Pequeño helper para no romper si la fila usa mayúsculas distintas
function existing_user_safe(u) {
  return u.id_usuario;
}

module.exports = {
  registerChallenge,
  registerVerify,
  loginChallenge,
  loginVerify,
  logout,
};
