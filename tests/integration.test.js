'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { startTestServer } = require('./helpers/testServer');
const { SoftwareAuthenticator } = require('../tools/softwareAuthenticator');

let ctx;
let config;

before(async () => {
  // startTestServer() fija ORIGIN/RP_ID antes de cargar la configuración.
  ctx = await startTestServer();
  config = require('../src/config/env');
});

after(async () => {
  if (ctx) await ctx.cleanup();
});

function userEmail(name) {
  return `${ctx.prefix}${name}@cul.edu.co`;
}

async function registerUser({
  email,
  nombre = 'Empleado de Prueba',
  rol = 'usuario',
  authenticator,
  attachment = 'platform',
}) {
  const auth = authenticator || new SoftwareAuthenticator({ origin: ctx.origin, attachment });

  const challenge = await ctx.client.post('/api/auth/register-challenge', {
    email,
    nombre_completo: nombre,
    rol,
  });
  assert.equal(challenge.status, 200, JSON.stringify(challenge.data));

  const attResp = await auth.register(challenge.data);
  const verified = await ctx.client.post('/api/auth/register-verify', {
    email,
    attResp,
  });
  assert.equal(verified.status, 200, JSON.stringify(verified.data));

  return { auth, user: verified.data.user, options: challenge.data };
}

async function loginUser(email, auth) {
  const challenge = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(challenge.status, 200, JSON.stringify(challenge.data));

  const asseResp = await auth.authenticate(challenge.data);
  const verified = await ctx.client.post('/api/auth/login-verify', { email, asseResp });
  return { verified, challenge: challenge.data, asseResp };
}

// ---------------------------------------------------------------------------
// Flujo principal
// ---------------------------------------------------------------------------
test('registro + login + RBAC + logout revoca la sesión', async () => {
  const email = userEmail('admin');
  const { auth, user, options } = await registerUser({
    email,
    nombre: 'Admin PyME',
    rol: 'admin',
  });

  assert.equal(user.email, email);
  assert.equal(user.rol, 'admin');
  assert.equal(options.authenticatorSelection.authenticatorAttachment, undefined);
  assert.equal(options.authenticatorSelection.userVerification, 'preferred');
  assert.equal(options.rp.id, 'localhost');

  const { verified } = await loginUser(email, auth);
  assert.equal(verified.status, 200, JSON.stringify(verified.data));
  assert.ok(verified.data.token);
  assert.ok(verified.data.id_sesion);

  const payload = jwt.decode(verified.data.token);
  assert.equal(payload.jti, verified.data.id_sesion);
  assert.equal(payload.rol, 'admin');
  assert.equal(payload.iss, config.jwtIssuer);
  assert.equal(payload.aud, config.jwtAudience);

  const dashboard = await ctx.client.get('/api/dashboard/pyme-data', {
    token: verified.data.token,
  });
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.data.nivel_acceso, 'total');
  assert.ok(dashboard.data.modulos.some((m) => m.id === 'usuarios'));

  const logout = await ctx.client.post('/api/auth/logout', {}, verified.data.token);
  assert.equal(logout.status, 200);

  const afterLogout = await ctx.client.get('/api/dashboard/pyme-data', {
    token: verified.data.token,
  });
  assert.equal(afterLogout.status, 401);
});

// ---------------------------------------------------------------------------
// Autenticadores de plataforma y externos
// ---------------------------------------------------------------------------
test('acepta un segundo autenticador cross-platform (YubiKey) para el mismo usuario', async () => {
  const email = userEmail('multikey');
  const { auth: platformAuth } = await registerUser({
    email,
    rol: 'operativo',
    attachment: 'platform',
  });

  // Para añadir una segunda llave a una cuenta existente hay que estar
  // autenticado con esa cuenta.
  const { verified: session } = await loginUser(email, platformAuth);
  assert.equal(session.status, 200);

  const yubikey = new SoftwareAuthenticator({
    origin: ctx.origin,
    attachment: 'cross-platform',
  });

  const challenge = await ctx.client.post(
    '/api/auth/register-challenge',
    {
      email,
      nombre_completo: 'Empleado Multikey',
      rol: 'operativo',
    },
    session.data.token
  );
  assert.equal(challenge.status, 200, JSON.stringify(challenge.data));

  const attResp = await yubikey.register(challenge.data);
  const verified = await ctx.client.post(
    '/api/auth/register-verify',
    { email, attResp },
    session.data.token
  );
  assert.equal(verified.status, 200, JSON.stringify(verified.data));

  const { rows } = await ctx.db.query(
    `SELECT c.tipo_autenticador
       FROM credenciales_webauthn c
       JOIN usuarios u ON u.id_usuario = c.id_usuario
      WHERE u.email = $1
      ORDER BY c.tipo_autenticador`,
    [email]
  );
  assert.deepEqual(
    rows.map((row) => row.tipo_autenticador),
    ['cross-platform', 'platform']
  );

  // Login con la llave externa (la de plataforma sigue registrada).
  const { verified: login } = await loginUser(email, yubikey);
  assert.equal(login.status, 200, JSON.stringify(login.data));
  assert.equal(login.data.user.rol, 'operativo');

  // Y también con la credencial de plataforma original.
  const { verified: login2 } = await loginUser(email, platformAuth);
  assert.equal(login2.status, 200, JSON.stringify(login2.data));
});

test('no permite añadir una llave a una cuenta existente sin autenticarse', async () => {
  const email = userEmail('takeover');
  await registerUser({ email, rol: 'usuario' });

  const challenge = await ctx.client.post('/api/auth/register-challenge', {
    email,
    nombre_completo: 'Atacante',
    rol: 'admin',
  });

  assert.equal(challenge.status, 403);
  assert.match(challenge.data.error, /iniciar sesión/i);
});

test('un usuario autenticado no puede auto-escalar su rol al añadir otra llave', async () => {
  const email = userEmail('self-escalate');
  const { auth } = await registerUser({ email, rol: 'usuario' });

  const { verified: session } = await loginUser(email, auth);
  assert.equal(session.status, 200);

  const challenge = await ctx.client.post(
    '/api/auth/register-challenge',
    { email, nombre_completo: 'Yo Mismo', rol: 'admin' },
    session.data.token
  );
  assert.equal(challenge.status, 200, JSON.stringify(challenge.data));

  const secondKey = new SoftwareAuthenticator({
    origin: ctx.origin,
    attachment: 'cross-platform',
  });
  const attResp = await secondKey.register(challenge.data);
  const verified = await ctx.client.post(
    '/api/auth/register-verify',
    { email, attResp },
    session.data.token
  );

  assert.equal(verified.status, 200, JSON.stringify(verified.data));
  assert.equal(verified.data.user.rol, 'usuario');
});

// ---------------------------------------------------------------------------
// Replay y manipulación criptográfica
// ---------------------------------------------------------------------------
test('un challenge de login no puede reutilizarse (anti-replay)', async () => {
  const email = userEmail('replay');
  const { auth } = await registerUser({ email });

  const { verified, asseResp } = await loginUser(email, auth);
  assert.equal(verified.status, 200);

  const replay = await ctx.client.post('/api/auth/login-verify', { email, asseResp });
  assert.equal(replay.status, 400);
  assert.match(replay.data.error, /expirado|utilizado/i);
});

test('rechaza una assertion firmada para otro origin (anti-phishing)', async () => {
  const email = userEmail('phishing');
  const { auth } = await registerUser({ email });

  auth.origin = 'https://evil.example';

  const challenge = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(challenge.status, 200);

  const asseResp = await auth.authenticate(challenge.data);
  const verified = await ctx.client.post('/api/auth/login-verify', { email, asseResp });
  assert.equal(verified.status, 401);
});

test('rechaza un contador de firmas que retrocede (posible clonación)', async () => {
  const email = userEmail('clon');
  const { auth } = await registerUser({ email });

  const first = await loginUser(email, auth);
  assert.equal(first.verified.status, 200);

  // Simula un autenticador clonado que reutiliza el contador anterior.
  auth.counter = 0;

  const challenge = await ctx.client.post('/api/auth/login-challenge', { email });
  const asseResp = await auth.authenticate(challenge.data);
  const verified = await ctx.client.post('/api/auth/login-verify', { email, asseResp });
  assert.equal(verified.status, 401);
});

test('una credencial no puede registrarse en una segunda cuenta', async () => {
  const emailA = userEmail('owner-a');
  const emailB = userEmail('owner-b');
  const { auth } = await registerUser({ email: emailA });

  const challenge = await ctx.client.post('/api/auth/register-challenge', {
    email: emailB,
    nombre_completo: 'Otra Cuenta',
    rol: 'usuario',
  });
  assert.equal(challenge.status, 200);

  const attResp = await auth.register(challenge.data);
  const verified = await ctx.client.post('/api/auth/register-verify', {
    email: emailB,
    attResp,
  });
  assert.equal(verified.status, 409);
});

// ---------------------------------------------------------------------------
// Sesiones JWT
// ---------------------------------------------------------------------------
test('rechaza peticiones sin token, con token inválido y con token expirado', async () => {
  const email = userEmail('tokens');
  const { user, auth } = await registerUser({ email, rol: 'gerencia' });

  const noToken = await ctx.client.get('/api/dashboard/pyme-data');
  assert.equal(noToken.status, 401);

  const invalid = await ctx.client.get('/api/dashboard/pyme-data', {
    token: 'no-es-un-jwt',
  });
  assert.equal(invalid.status, 401);

  // Token correctamente firmado pero expirado, con sesión "activa" en BD.
  const idSesion = crypto.randomUUID();
  const expiredToken = jwt.sign(
    { id_usuario: user.id_usuario, email: user.email, rol: user.rol },
    config.jwtSecret,
    {
      expiresIn: -10,
      jwtid: idSesion,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      algorithm: 'HS256',
    }
  );
  await ctx.db.query(
    `INSERT INTO sesiones_iam (id_sesion, id_usuario, token_jwt, fecha_expiracion)
     VALUES ($1, $2, $3, $4)`,
    [idSesion, user.id_usuario, expiredToken, new Date(Date.now() + 3_600_000)]
  );

  const expired = await ctx.client.get('/api/dashboard/pyme-data', {
    token: expiredToken,
  });
  assert.equal(expired.status, 401);

  // Token válido cuya sesión fue eliminada directamente en PostgreSQL.
  const { verified } = await loginUser(email, auth);
  assert.equal(verified.status, 200);
  await ctx.db.query('DELETE FROM sesiones_iam WHERE id_sesion = $1', [
    verified.data.id_sesion,
  ]);
  const revoked = await ctx.client.get('/api/dashboard/pyme-data', {
    token: verified.data.token,
  });
  assert.equal(revoked.status, 401);
});

test('un usuario deshabilitado pierde el acceso y no obtiene retos', async () => {
  const email = userEmail('disabled');
  const { auth } = await registerUser({ email });

  const { verified } = await loginUser(email, auth);
  assert.equal(verified.status, 200);

  await ctx.db.query('UPDATE usuarios SET estado = FALSE WHERE email = $1', [email]);

  const dashboard = await ctx.client.get('/api/dashboard/pyme-data', {
    token: verified.data.token,
  });
  assert.equal(dashboard.status, 401);

  const challenge = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(challenge.status, 404);
  assert.doesNotMatch(challenge.data.error, /registrado|deshabilitado/i);
});

// ---------------------------------------------------------------------------
// RBAC y validación de entrada
// ---------------------------------------------------------------------------
test('RBAC: operativo y gerencia reciben módulos distintos', async () => {
  const operativoEmail = userEmail('operativo');
  const gerenciaEmail = userEmail('gerencia');

  const { auth: operativoAuth } = await registerUser({
    email: operativoEmail,
    rol: 'operativo',
  });
  const { auth: gerenciaAuth } = await registerUser({
    email: gerenciaEmail,
    rol: 'gerencia',
  });

  const { verified: operativoLogin } = await loginUser(operativoEmail, operativoAuth);
  const operativoDash = await ctx.client.get('/api/dashboard/pyme-data', {
    token: operativoLogin.data.token,
  });
  assert.equal(operativoDash.status, 200);
  assert.equal(operativoDash.data.nivel_acceso, 'medio');
  assert.ok(operativoDash.data.modulos.some((m) => m.id === 'inventario'));
  assert.ok(!operativoDash.data.modulos.some((m) => m.id === 'usuarios'));

  const { verified: gerenciaLogin } = await loginUser(gerenciaEmail, gerenciaAuth);
  const gerenciaDash = await ctx.client.get('/api/dashboard/pyme-data', {
    token: gerenciaLogin.data.token,
  });
  assert.equal(gerenciaDash.status, 200);
  assert.equal(gerenciaDash.data.nivel_acceso, 'alto');
  assert.ok(gerenciaDash.data.modulos.some((m) => m.id === 'reportes'));
});

test('rechaza roles y emails inválidos', async () => {
  const role = await ctx.client.post('/api/auth/register-challenge', {
    email: userEmail('bad-role'),
    nombre_completo: 'Rol Malo',
    rol: 'superadmin',
  });
  assert.equal(role.status, 400);

  const email = await ctx.client.post('/api/auth/register-challenge', {
    email: 'no-es-un-email',
    nombre_completo: 'Email Malo',
    rol: 'usuario',
  });
  assert.equal(email.status, 400);

  const name = await ctx.client.post('/api/auth/register-challenge', {
    email: userEmail('long-name'),
    nombre_completo: 'x'.repeat(300),
    rol: 'usuario',
  });
  assert.equal(name.status, 400);
});

test('el rol no puede alterarse entre challenge y verify', async () => {
  const email = userEmail('tamper');
  const auth = new SoftwareAuthenticator({ origin: ctx.origin });

  const challenge = await ctx.client.post('/api/auth/register-challenge', {
    email,
    nombre_completo: 'Sin Privilegios',
    rol: 'usuario',
  });
  assert.equal(challenge.status, 200);

  const attResp = await auth.register(challenge.data);
  const verified = await ctx.client.post('/api/auth/register-verify', {
    email,
    attResp,
    rol: 'admin', // intento de escalada: el servidor debe ignorarlo
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.data.user.rol, 'usuario');
});

test('login-challenge responde igual para email inexistente y usuario deshabilitado', async () => {
  const unknown = await ctx.client.post('/api/auth/login-challenge', {
    email: userEmail('no-existe'),
  });
  assert.equal(unknown.status, 404);

  const email = userEmail('disabled-enum');
  await registerUser({ email });
  await ctx.db.query('UPDATE usuarios SET estado = FALSE WHERE email = $1', [email]);

  const disabled = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(disabled.status, 404);
  assert.equal(disabled.data.error, unknown.data.error);
});

test('logout es idempotente y limpia la cookie', async () => {
  const first = await ctx.client.post('/api/auth/logout', {});
  assert.equal(first.status, 200);
  assert.match(String(first.headers.get('set-cookie')), /iam_token=;/);

  const second = await ctx.client.post('/api/auth/logout', {});
  assert.equal(second.status, 200);
});
