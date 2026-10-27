'use strict';

process.env.RATE_LIMIT_STRICT_MAX = '2';
process.env.RATE_LIMIT_STRICT_WINDOW_MS = '60000';
process.env.RATE_LIMIT_MAX = '1000';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { startTestServer } = require('./helpers/testServer');

let ctx;

before(async () => {
  ctx = await startTestServer();
});

after(async () => {
  if (ctx) await ctx.cleanup();
});

test('limita los intentos de login-challenge por IP y ruta', async () => {
  const email = `${ctx.prefix}rate@cul.edu.co`;

  const first = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(first.status, 404);

  const second = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(second.status, 404);

  const third = await ctx.client.post('/api/auth/login-challenge', { email });
  assert.equal(third.status, 429);
  assert.ok(Number(third.headers.get('retry-after')) >= 1);
  assert.match(third.data.error, /Demasiados intentos/i);
});
