'use strict';

process.env.ALLOW_PUBLIC_ROLE_SELECTION = 'false';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { startTestServer } = require('./helpers/testServer');

let ctx;
let db;
let signSessionToken;

before(async () => {
  ctx = await startTestServer();
  db = ctx.db;
  signSessionToken = require('../src/services/tokenService').signSessionToken;
});

after(async () => {
  if (ctx) await ctx.cleanup();
});

async function createSessionFor(user) {
  const idSesion = crypto.randomUUID();
  const token = signSessionToken(user, idSesion);
  await db.query(
    `INSERT INTO sesiones_iam (id_sesion, id_usuario, token_jwt, fecha_expiracion)
     VALUES ($1, $2, $3, $4)`,
    [idSesion, user.id_usuario, token, new Date(Date.now() + 3_600_000)]
  );
  return token;
}

test('sin sesión de admin no se pueden asignar roles elevados', async () => {
  const response = await ctx.client.post('/api/auth/register-challenge', {
    email: `${ctx.prefix}elevated@cul.edu.co`,
    nombre_completo: 'Intento Elevado',
    rol: 'admin',
  });
  assert.equal(response.status, 403);
});

test('el alta pública con rol usuario sigue permitida', async () => {
  const response = await ctx.client.post('/api/auth/register-challenge', {
    email: `${ctx.prefix}normal@cul.edu.co`,
    nombre_completo: 'Empleado Normal',
    rol: 'usuario',
  });
  assert.equal(response.status, 200);
});

test('un admin autenticado sí puede asignar roles elevados', async () => {
  const { rows } = await db.query(
    `INSERT INTO usuarios (email, nombre_completo, rol, estado)
     VALUES ($1, $2, 'admin', TRUE)
     RETURNING *`,
    [`${ctx.prefix}admin-directo@cul.edu.co`, 'Admin Directo']
  );
  const token = await createSessionFor(rows[0]);

  const allowed = await ctx.client.post(
    '/api/auth/register-challenge',
    {
      email: `${ctx.prefix}gerente@cul.edu.co`,
      nombre_completo: 'Gerente PyME',
      rol: 'gerencia',
    },
    token
  );
  assert.equal(allowed.status, 200, JSON.stringify(allowed.data));
});

test('un token de rol usuario no puede asignar roles elevados', async () => {
  const { rows } = await db.query(
    `INSERT INTO usuarios (email, nombre_completo, rol, estado)
     VALUES ($1, $2, 'usuario', TRUE)
     RETURNING *`,
    [`${ctx.prefix}usuario-directo@cul.edu.co`, 'Usuario Directo']
  );
  const token = await createSessionFor(rows[0]);

  const denied = await ctx.client.post(
    '/api/auth/register-challenge',
    {
      email: `${ctx.prefix}otro-admin@cul.edu.co`,
      nombre_completo: 'Otro Admin',
      rol: 'admin',
    },
    token
  );
  assert.equal(denied.status, 403);
});
