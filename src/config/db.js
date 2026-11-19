'use strict';

const { Pool } = require('pg');
require('dotenv').config();

const connectionString = String(process.env.DATABASE_URL || '').trim();
if (!connectionString) {
  throw new Error(
    '[db] DATABASE_URL es obligatorio (p. ej. postgres://usuario:clave@host:5432/base)'
  );
}

function parseBoolean(raw, fallback, name) {
  if (raw === undefined || raw === '') return fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'si', 'sí', 'on', 'require'].includes(value)) return true;
  if (['0', 'false', 'no', 'off', 'disable'].includes(value)) return false;
  throw new Error(`[db] ${name} debe ser true/false/auto (recibido: "${raw}")`);
}

function buildSslOptions() {
  const ca = String(process.env.DATABASE_SSL_CA || '')
    .replace(/\\n/g, '\n')
    .trim();
  const rejectUnauthorized = parseBoolean(
    process.env.DATABASE_SSL_REJECT_UNAUTHORIZED,
    Boolean(ca),
    'DATABASE_SSL_REJECT_UNAUTHORIZED'
  );

  return {
    rejectUnauthorized,
    ...(ca ? { ca } : {}),
  };
}

/**
 * SSL para PostgreSQL:
 * - DATABASE_SSL=false: desactivado (localhost o red interna de Railway).
 * - DATABASE_SSL=true: activado.
 * - DATABASE_SSL=auto (recomendado): activo para hosts públicos y desactivado
 *   para localhost, 127.0.0.1 y *.railway.internal.
 *
 * También respeta `sslmode` si viene dentro de DATABASE_URL.
 * Railway presenta certificados gestionados; para producción se usa
 * rejectUnauthorized=false salvo que se configure DATABASE_SSL_CA.
 */
function resolveSsl(connectionString) {
  let url = null;
  try {
    url = new URL(connectionString);
  } catch {
    // La validación principal de DATABASE_URL está en config/env.js.
  }

  const sslMode = (url?.searchParams.get('sslmode') || '').trim().toLowerCase();
  const raw = String(process.env.DATABASE_SSL || 'auto').trim().toLowerCase();

  if (['false', '0', 'no', 'off', 'disable'].includes(raw)) return false;
  if (['true', '1', 'yes', 'si', 'sí', 'on', 'require'].includes(raw)) {
    return buildSslOptions();
  }
  if (raw !== 'auto' && raw !== '') {
    throw new Error(`[db] DATABASE_SSL debe ser auto/true/false (recibido: "${raw}")`);
  }

  if (sslMode === 'disable') return false;
  if (['require', 'no-verify', 'prefer'].includes(sslMode)) return buildSslOptions();
  if (['verify-full', 'verify-ca'].includes(sslMode)) {
    return { ...buildSslOptions(), rejectUnauthorized: true };
  }

  const host = (url?.hostname || '').toLowerCase();
  if (!host) return false;

  const isLocalOrRailwayInternal =
    ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host) ||
    host.endsWith('.railway.internal');

  return isLocalOrRailwayInternal ? false : buildSslOptions();
}

const ssl = resolveSsl(connectionString);

// Pool de conexiones a PostgreSQL.
const pool = new Pool({
  connectionString,
  ssl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  keepAlive: true,
  application_name: 'zisxa-iam',
});

// Manejo de errores inesperados del pool (por ejemplo, caída de PostgreSQL).
// El arranque no se tumba aquí: /api/health reporta el estado de la BD.
pool.on('error', (err) => {
  console.error('[db] Error inesperado en el pool:', err.message);
});

module.exports = {
  // query(text, params) -> { rows, rowCount, ... }
  query: (text, params) => pool.query(text, params),
  pool,
  sslEnabled: Boolean(ssl),
};
