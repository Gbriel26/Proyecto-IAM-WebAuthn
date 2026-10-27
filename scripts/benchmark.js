'use strict';

/**
 * Benchmark reproducible del ciclo de autenticación IAM/WebAuthn.
 *
 * Mide, sobre HTTP real y PostgreSQL real:
 *   1. Generación del challenge            (login-challenge)
 *   2. Firma local ES256                   (autenticador de software)
 *   3. Verificación de firma + JWT + sesión (login-verify)
 *   4. Middleware JWT + RBAC               (dashboard)
 *
 * La firma local de software es una COTA INFERIOR de la "Ceremonia
 * Criptográfica Local" de la Tabla 5: Windows Hello/TPM añade la interacción
 * biométrica humana (~1 s), que no es medible desde el servidor.
 *
 * Uso:
 *   npm run benchmark
 *   BENCH_ITERATIONS=50 npm run benchmark
 */

const fs = require('fs');
const path = require('path');
const { performance } = require('node:perf_hooks');
const { once } = require('node:events');

const { getFreePort } = require('../tools/freePort');

const ITERATIONS = Number(process.env.BENCH_ITERATIONS || 20);
const WARMUP = Number(process.env.BENCH_WARMUP || 3);

function stats(samples) {
  const n = samples.length;
  const sum = samples.reduce((acc, value) => acc + value, 0);
  const mean = sum / n;
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const variance =
    n > 1
      ? samples.reduce((acc, value) => acc + (value - mean) ** 2, 0) / (n - 1)
      : 0;

  return {
    mean,
    min,
    max,
    stddev: Math.sqrt(variance),
    samples: samples.map((value) => Number(value.toFixed(3))),
  };
}

function format(value) {
  return value.toFixed(1).replace('.', ',');
}

async function main() {
  if (!Number.isInteger(ITERATIONS) || ITERATIONS < 1) {
    throw new Error('BENCH_ITERATIONS debe ser un entero >= 1');
  }

  const port = await getFreePort();
  const origin = `http://localhost:${port}`;

  process.env.NODE_ENV = 'benchmark';
  process.env.ORIGIN = origin;
  process.env.RP_ID = 'localhost';
  process.env.RATE_LIMIT_MAX = '100000';
  process.env.RATE_LIMIT_STRICT_MAX = '100000';

  // Se requiere DESPUÉS de fijar ORIGIN/RP_ID.
  const app = require('../src/app');
  const db = require('../src/config/db');
  const { SoftwareAuthenticator } = require('../tools/softwareAuthenticator');

  const schema = fs.readFileSync(path.join(__dirname, '..', 'src', 'schema.sql'), 'utf8');
  await db.query(schema);

  const server = app.listen(port);
  await once(server, 'listening');

  const email = `bench+${Date.now()}@cul.edu.co`;

  async function request(pathname, { method = 'GET', body, token } = {}) {
    const response = await fetch(origin + pathname, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    return { status: response.status, data };
  }

  try {
    // ------------------------------------------------------------------
    // Alta del usuario de prueba (no se mide)
    // ------------------------------------------------------------------
    const authenticator = new SoftwareAuthenticator({
      origin,
      attachment: 'platform',
    });

    const regChallenge = await request('/api/auth/register-challenge', {
      method: 'POST',
      body: { email, nombre_completo: 'Benchmark IAM', rol: 'admin' },
    });
    if (regChallenge.status !== 200) {
      throw new Error(`register-challenge falló: ${JSON.stringify(regChallenge.data)}`);
    }

    const attResp = await authenticator.register(regChallenge.data);
    const regVerify = await request('/api/auth/register-verify', {
      method: 'POST',
      body: { email, attResp },
    });
    if (regVerify.status !== 200) {
      throw new Error(`register-verify falló: ${JSON.stringify(regVerify.data)}`);
    }

    // ------------------------------------------------------------------
    // Medición
    // ------------------------------------------------------------------
    const challengeSamples = [];
    const localSamples = [];
    const verifySamples = [];
    const middlewareSamples = [];

    const total = ITERATIONS + WARMUP;

    for (let i = 0; i < total; i += 1) {
      const t0 = performance.now();
      const challenge = await request('/api/auth/login-challenge', {
        method: 'POST',
        body: { email },
      });
      const t1 = performance.now();

      if (challenge.status !== 200) {
        throw new Error(`login-challenge falló: ${JSON.stringify(challenge.data)}`);
      }

      const assertion = await authenticator.authenticate(challenge.data);
      const t2 = performance.now();

      const verified = await request('/api/auth/login-verify', {
        method: 'POST',
        body: { email, asseResp: assertion },
      });
      const t3 = performance.now();

      if (verified.status !== 200) {
        throw new Error(`login-verify falló: ${JSON.stringify(verified.data)}`);
      }

      const dashboard = await request('/api/dashboard/pyme-data', {
        token: verified.data.token,
      });
      const t4 = performance.now();

      if (dashboard.status !== 200) {
        throw new Error(`dashboard falló: ${JSON.stringify(dashboard.data)}`);
      }

      if (i >= WARMUP) {
        challengeSamples.push(t1 - t0);
        localSamples.push(t2 - t1);
        verifySamples.push(t3 - t2);
        middlewareSamples.push(t4 - t3);
      }
    }

    const results = {
      challenge: stats(challengeSamples),
      local: stats(localSamples),
      verify: stats(verifySamples),
      middleware: stats(middlewareSamples),
    };

    const table = [
      ['Generación de Challenge (/api/auth/login-challenge)', results.challenge],
      ['Ceremonia local ES256 (software, cota inferior)', results.local],
      ['Validación de Firma + JWT + Sesión (/api/auth/login-verify)', results.verify],
      ['Validación Middleware RBAC (/api/dashboard/pyme-data)', results.middleware],
    ];

    console.log('');
    console.log('Benchmark IAM/WebAuthn');
    console.log(`Iteraciones medidas: ${ITERATIONS} (+${WARMUP} de calentamiento)`);
    console.log(`Node ${process.version} | ${process.platform} | ${origin}`);
    console.log('');
    console.log('| Fase | Media (ms) | Mín (ms) | Máx (ms) | Desv. estándar (ms) |');
    console.log('|---|---:|---:|---:|---:|');
    for (const [name, result] of table) {
      console.log(
        `| ${name} | ${format(result.mean)} | ${format(result.min)} | ${format(result.max)} | ${format(result.stddev)} |`
      );
    }
    console.log('');
    console.log(
      'Nota: la ceremonia local con Windows Hello/TPM incluye interacción humana (~1 s). ' +
        'Aquí se mide solo la firma ES256 de software para aislar el backend.'
    );

    const output = {
      generatedAt: new Date().toISOString(),
      environment: {
        node: process.version,
        platform: process.platform,
        rpId: 'localhost',
        origin,
        iterations: ITERATIONS,
        warmup: WARMUP,
      },
      results,
    };

    const outputPath = path.join(__dirname, '..', 'docs', 'benchmark-results.json');
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
    console.log(`Resultados guardados en ${path.relative(process.cwd(), outputPath)}`);
  } finally {
    await db.query('DELETE FROM usuarios WHERE email = $1', [email]).catch(() => {});
    server.closeIdleConnections?.();
    await new Promise((resolve) => server.close(resolve));
    await db.pool.end();
  }
}

main().catch((err) => {
  console.error('[benchmark]', err);
  process.exit(1);
});
