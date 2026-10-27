'use strict';

const db = require('../config/db');
const config = require('../config/env');
const { verifySessionToken } = require('../services/tokenService');

/**
 * Middleware de autenticación IAM.
 *
 * 1. Extrae el Token JWT de Acceso Unificado de `Authorization: Bearer ...`
 *    o de la cookie httpOnly de sesión.
 * 2. Verifica firma, expiración, emisor y audiencia.
 * 3. Valida que la sesión siga existiendo en PostgreSQL (revocación por
 *    logout), que no haya expirado y que el usuario siga activo.
 *
 * La búsqueda usa `jti` (= id_sesion, clave primaria), no el token completo:
 * es O(log n) y evita escanear secuencialmente `sesiones_iam`.
 */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  const token =
    (match ? match[1].trim() : null) ||
    req.cookies?.[config.sessionCookieName] ||
    null;

  if (!token) {
    return res.status(401).json({
      error: 'Falta el Token JWT de Acceso Unificado (Authorization: Bearer <token>)',
    });
  }

  let payload;
  try {
    payload = verifySessionToken(token);
  } catch {
    return res.status(401).json({
      error: 'Token JWT de Acceso Unificado inválido o expirado',
    });
  }

  if (!payload.jti || !payload.id_usuario) {
    return res.status(401).json({ error: 'Token JWT sin identificador de sesión' });
  }

  let session;
  try {
    const { rows } = await db.query(
      `SELECT s.id_sesion, u.rol
         FROM sesiones_iam s
         JOIN usuarios u ON u.id_usuario = s.id_usuario
        WHERE s.id_sesion = $1
          AND s.id_usuario = $2
          AND s.fecha_expiracion > NOW()
          AND u.estado = TRUE`,
      [payload.jti, payload.id_usuario]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        error: 'Sesión IAM inexistente, expirada, revocada o usuario deshabilitado',
      });
    }
    session = rows[0];
  } catch (err) {
    console.error(`[auth-middleware][${req.id || '-'}]`, err.message);
    return res.status(500).json({
      error: 'No se pudo validar la sesión en PostgreSQL',
      request_id: req.id,
    });
  }

  req.user = {
    id_usuario: payload.id_usuario,
    email: payload.email,
    // El rol vigente se lee de PostgreSQL: una degradación de privilegios
    // surte efecto de inmediato, sin esperar a que expire el JWT.
    rol: session.rol,
  };
  req.token = token;
  req.sessionId = payload.jti;
  return next();
}

module.exports = { requireAuth };
