'use strict';

const fs = require('fs');
const path = require('path');
const { once } = require('events');

const { getFreePort } = require('../../tools/freePort');

/**
 * Levanta la app real en un puerto efímero con su propio ORIGIN.
 * Debe llamarse ANTES de requerir src/app para que la configuración
 * congele el origin y el RP ID correctos.
 */
async function startTestServer({ prefix } = {}) {
  const port = await getFreePort();
  const origin = `http://localhost:${port}`;

  process.env.NODE_ENV = 'test';
  process.env.ORIGIN = origin;
  process.env.RP_ID = 'localhost';
  process.env.RATE_LIMIT_MAX = process.env.RATE_LIMIT_MAX || '10000';
  process.env.RATE_LIMIT_STRICT_MAX = process.env.RATE_LIMIT_STRICT_MAX || '10000';

  // eslint-disable-next-line global-require
  const app = require('../../src/app');
  // eslint-disable-next-line global-require
  const db = require('../../src/config/db');

  const schema = fs.readFileSync(
    path.join(__dirname, '..', '..', 'src', 'schema.sql'),
    'utf8'
  );
  await db.query(schema);

  const server = app.listen(port);
  await once(server, 'listening');

  const userPrefix = prefix || `test+${Date.now()}+`;

  async function request(pathname, { method = 'GET', body, token, headers = {} } = {}) {
    const response = await fetch(origin + pathname, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual',
    });

    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    return { status: response.status, data, headers: response.headers };
  }

  return {
    app,
    db,
    server,
    origin,
    port,
    prefix: userPrefix,
    client: {
      request,
      get: (pathname, options) => request(pathname, { ...options, method: 'GET' }),
      post: (pathname, body, token) =>
        request(pathname, { method: 'POST', body, token }),
    },
    async cleanup() {
      server.closeIdleConnections?.();
      await new Promise((resolve) => server.close(resolve));
      try {
        await db.query('DELETE FROM usuarios WHERE email LIKE $1', [`${userPrefix}%`]);
      } finally {
        await db.pool.end();
      }
    },
    async cleanupUsers() {
      await db.query('DELETE FROM usuarios WHERE email LIKE $1', [`${userPrefix}%`]);
    },
  };
}

module.exports = { startTestServer, getFreePort };
