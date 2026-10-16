const jwt = require('jsonwebtoken');
const db = require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

/**
 * Middleware de autenticación IAM.
 * Espera el Token JWT de Acceso Unificado en:
 *   Authorization: Bearer <token>
 * 1. Verifica la firma y expiración del JWT.
 * 2. Comprueba que la sesión siga activa en `sesiones_iam`
 *    (así el /api/auth/logout invalida el token aunque no haya expirado).
 * En caso válido adjunta `req.user = { id_usuario, email, rol }`.
 */
async function requireAuth(req, res, next) {
  // Esquema Bearer insensible a mayúsculas (RFC 6750) y tolerante a
  // espacios extra, para no rechazar tokens válidos por formato.
  const match = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  const token = match ? match[1].trim() : null;

  if (!token) {
    return res.status(401).json({ error: 'Falta el Token JWT de Acceso Unificado (Authorization: Bearer <token>)' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Token JWT de Acceso Unificado inválido o expirado' });
  }

  try {
    // Solo se exige EXISTENCIA de la sesión: el logout la elimina (DELETE)
    // y eso basta para revocarla. La expiración ya la aplica jwt.verify()
    // con el claim `exp` (reloj del servidor, sin ambigüedad de zona horaria).
    // NOTA: no se filtra por `fecha_expiracion > NOW()` porque esa columna es
    // `timestamp without time zone` y la comparación depende del TimeZone de
    // la BD (p. ej. app en UTC-5 + BD en GMT ⇒ sesiones válidas parecían
    // expiradas y el middleware las rechazaba con 401 falsos).
    const { rows } = await db.query(
      'SELECT id_sesion FROM sesiones_iam WHERE token_jwt = $1',
      [token]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Sesión IAM inexistente o cerrada (logout previo)' });
    }
  } catch (err) {
    console.error('[auth-middleware]', err.message);
    return res.status(500).json({ error: 'No se pudo validar la sesión en PostgreSQL' });
  }

  req.user = {
    id_usuario: payload.id_usuario,
    email: payload.email,
    rol: payload.rol,
  };
  req.token = token;
  return next();
}

module.exports = { requireAuth };
