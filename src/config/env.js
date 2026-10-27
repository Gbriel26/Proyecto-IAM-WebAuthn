'use strict';

/**
 * Configuración central del middleware IAM.
 *
 * Regla de oro: la aplicación NO arranca si falta un secreto crítico.
 * Antes existía un fallback `'dev-secret'`, lo que permitía firmar JWT con
 * un valor público si `.env` no se cargaba. Eso queda prohibido.
 */

require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

function fail(message) {
  throw new Error(`[iam][config] ${message}`);
}

function parseBoolean(raw, fallback, name) {
  if (raw === undefined || raw === '') return fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'si', 'sí'].includes(value)) return true;
  if (['0', 'false', 'no'].includes(value)) return false;
  return fail(`${name} debe ser true/false (recibido: "${raw}")`);
}

function parseInteger(raw, fallback, { name, min, max }) {
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) fail(`${name} debe ser un entero (recibido: "${raw}")`);
  if (min !== undefined && value < min) fail(`${name} debe ser >= ${min}`);
  if (max !== undefined && value > max) fail(`${name} debe ser <= ${max}`);
  return value;
}

function normalizeOrigin(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return fail(`ORIGIN inválido: "${raw}". Ejemplo: http://localhost:3000`);
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    fail(`ORIGIN debe usar http o https: "${raw}"`);
  }
  return url.origin;
}

function parseOrigins(raw, fallbackPort) {
  const parts = String(raw || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (parts.length === 0) parts.push(`http://localhost:${fallbackPort}`);
  return [...new Set(parts.map(normalizeOrigin))];
}

if (!process.env.DATABASE_URL || !String(process.env.DATABASE_URL).trim()) {
  fail(
    'DATABASE_URL es obligatorio (p. ej. postgres://usuario:clave@localhost:5432/iam_webauthn)'
  );
}

const port = parseInteger(process.env.PORT, 3000, {
  name: 'PORT',
  min: 1,
  max: 65535,
});

const jwtSecret = String(process.env.JWT_SECRET || '');
if (jwtSecret.length < 32) {
  fail(
    'JWT_SECRET es obligatorio y debe tener al menos 32 caracteres. ' +
      'Genera uno con: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"'
  );
}
const PLACEHOLDER_SECRETS = new Set([
  'CAMBIA_ESTE_SECRETO_POR_UNO_DE_AL_MENOS_32_CARACTERES',
  'cambia-esto-por-un-secreto-de-al-menos-32-caracteres',
  'cambia_este_secreto_por_uno_de_al_menos_32_caracteres',
  'changeme',
  'dev-secret',
]);
if (PLACEHOLDER_SECRETS.has(jwtSecret)) {
  fail('JWT_SECRET sigue siendo un valor de ejemplo. Genera uno real antes de arrancar.');
}

const rpId = String(process.env.RP_ID || 'localhost').trim();
if (!rpId || rpId.includes('://') || rpId.includes('/')) {
  fail(`RP_ID debe ser un dominio sin esquema ni ruta (recibido: "${rpId}")`);
}

const rpName = String(process.env.RP_NAME || 'IAM PyME').trim() || 'IAM PyME';

const origins = parseOrigins(process.env.ORIGIN, port);

if (isProduction) {
  if (!process.env.ORIGIN) {
    fail('ORIGIN es obligatorio en producción (p. ej. https://iam.mipyme.com)');
  }
  if (origins.some((origin) => !origin.startsWith('https://'))) {
    fail('En producción ORIGIN debe usar https:// (WebAuthn lo exige fuera de localhost)');
  }
  if (rpId === 'localhost') {
    fail('RP_ID no puede ser "localhost" en producción');
  }
}

const sessionTtlMs = parseInteger(process.env.SESSION_TTL_MS, 60 * 60 * 1000, {
  name: 'SESSION_TTL_MS',
  min: 30_000,
  max: 30 * 24 * 60 * 60 * 1000,
});

const challengeTtlMs = parseInteger(process.env.CHALLENGE_TTL_MS, 5 * 60 * 1000, {
  name: 'CHALLENGE_TTL_MS',
  min: 1_000,
  max: 15 * 60 * 1000,
});

const rateLimitWindowMs = parseInteger(process.env.RATE_LIMIT_WINDOW_MS, 60_000, {
  name: 'RATE_LIMIT_WINDOW_MS',
  min: 1_000,
  max: 60 * 60 * 1000,
});
const rateLimitMax = parseInteger(process.env.RATE_LIMIT_MAX, 120, {
  name: 'RATE_LIMIT_MAX',
  min: 1,
  max: 100_000,
});
const rateLimitStrictWindowMs = parseInteger(
  process.env.RATE_LIMIT_STRICT_WINDOW_MS,
  60_000,
  { name: 'RATE_LIMIT_STRICT_WINDOW_MS', min: 1_000, max: 60 * 60 * 1000 }
);
const rateLimitStrictMax = parseInteger(process.env.RATE_LIMIT_STRICT_MAX, 30, {
  name: 'RATE_LIMIT_STRICT_MAX',
  min: 1,
  max: 100_000,
});

let trustProxy = false;
if (process.env.TRUST_PROXY !== undefined && process.env.TRUST_PROXY !== '') {
  const raw = String(process.env.TRUST_PROXY).trim();
  trustProxy = /^\d+$/.test(raw) ? Number(raw) : parseBoolean(raw, false, 'TRUST_PROXY');
}

const sessionCookieName = String(process.env.SESSION_COOKIE_NAME || 'iam_token').trim();
if (!/^[A-Za-z0-9_-]+$/.test(sessionCookieName)) {
  fail(`SESSION_COOKIE_NAME inválido: "${sessionCookieName}"`);
}

const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction,
  port,
  rpId,
  rpName,
  origins,
  primaryOrigin: origins[0],
  jwtSecret,
  jwtExpiresInSeconds: Math.floor(sessionTtlMs / 1000),
  jwtIssuer: process.env.JWT_ISSUER || 'iam-webauthn-cul',
  jwtAudience: process.env.JWT_AUDIENCE || 'pyme-iam',
  sessionTtlMs,
  sessionCookieName,
  cookieSecure: parseBoolean(process.env.COOKIE_SECURE, isProduction, 'COOKIE_SECURE'),
  challengeTtlMs,
  maxChallenges: 10_000,
  rateLimit: {
    windowMs: rateLimitWindowMs,
    max: rateLimitMax,
    strictWindowMs: rateLimitStrictWindowMs,
    strictMax: rateLimitStrictMax,
  },
  trustProxy,
  // En desarrollo/demo se permite elegir rol en el alta pública para poder
  // mostrar el RBAC sin un administrador previo. En producción el valor por
  // defecto es false: solo un admin autenticado (o el primer usuario) puede
  // asignar roles elevados.
  allowPublicRoleSelection: parseBoolean(
    process.env.ALLOW_PUBLIC_ROLE_SELECTION,
    !isProduction,
    'ALLOW_PUBLIC_ROLE_SELECTION'
  ),
};

module.exports = Object.freeze(config);
