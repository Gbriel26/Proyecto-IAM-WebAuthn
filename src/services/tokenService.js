'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config/env');

/**
 * Emite el Token JWT de Acceso Unificado.
 *
 * El claim `jti` es el `id_sesion` de PostgreSQL. Gracias a él el middleware
 * busca la sesión por la clave primaria (O(log n)) en lugar de comparar el
 * token completo contra toda la tabla, y el logout puede revocar la sesión
 * sin exponer el token en las consultas.
 */
function signSessionToken(user, idSesion) {
  return jwt.sign(
    {
      id_usuario: user.id_usuario,
      email: user.email,
      rol: user.rol,
    },
    config.jwtSecret,
    {
      expiresIn: config.jwtExpiresInSeconds,
      jwtid: idSesion,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      algorithm: 'HS256',
    }
  );
}

/**
 * Verifica firma, expiración, emisor y audiencia.
 * Lanza si el token no es válido.
 */
function verifySessionToken(token) {
  return jwt.verify(token, config.jwtSecret, {
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    algorithms: ['HS256'],
    clockTolerance: 5,
  });
}

/**
 * Verifica la firma aunque el token esté expirado. Se usa únicamente en el
 * logout para poder revocar una sesión caducada sin aceptar jti falsificados.
 */
function verifySessionTokenIgnoringExpiration(token) {
  return jwt.verify(token, config.jwtSecret, {
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    algorithms: ['HS256'],
    ignoreExpiration: true,
  });
}

module.exports = {
  signSessionToken,
  verifySessionToken,
  verifySessionTokenIgnoringExpiration,
};
