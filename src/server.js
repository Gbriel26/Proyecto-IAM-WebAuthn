'use strict';

const fs = require('fs');
const path = require('path');

// Valida la configuración antes de arrancar (lanza si falta JWT_SECRET, etc.).
const config = require('./config/env');
const app = require('./app');
const db = require('./config/db');

async function initDb() {
  // Crea/migra las tablas y los roles base a partir de src/schema.sql.
  // En producción se reintenta: Railway puede arrancar la app antes de que
  // PostgreSQL termine de aceptar conexiones.
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  const attempts = config.isProduction ? 10 : 1;
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await db.query(sql);
      console.log(
        '[iam] Esquema verificado (roles, usuarios, credenciales_webauthn, sesiones_iam)'
      );
      return;
    } catch (err) {
      lastError = err;
      if (attempt < attempts) {
        console.warn(
          `[iam] PostgreSQL aún no está listo (intento ${attempt}/${attempts}): ${err.message}`
        );
        await new Promise((resolve) => setTimeout(resolve, 3_000));
      }
    }
  }

  throw lastError;
}

async function main() {
  try {
    await initDb();
  } catch (err) {
    console.error('[iam] No se pudo inicializar la BD. ¿DATABASE_URL correcta y Postgres activo?');
    console.error(`[iam] ${err.message}`);
    if (config.isProduction) process.exit(1);
  }

  if (config.allowPublicRoleSelection) {
    console.warn(
      '[iam][seguridad] ALLOW_PUBLIC_ROLE_SELECTION=true: el alta pública permite elegir rol. ' +
        'En producción define ALLOW_PUBLIC_ROLE_SELECTION=false.'
    );
  }

  const server = app.listen(config.port, config.host, () => {
    console.log(`[iam] Servidor IAM escuchando en ${config.host}:${config.port}`);
    console.log(`[iam] URL pública esperada: ${config.primaryOrigin}`);
    console.log(`[iam] RP_ID=${config.rpId} RP_NAME=${config.rpName}`);
    console.log(`[iam] Orígenes permitidos: ${config.origins.join(', ')}`);
  });

  server.on('error', (err) => {
    console.error(`[iam] No se pudo abrir el puerto ${config.port}: ${err.message}`);
    process.exit(1);
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[iam] ${signal} recibido: cerrando servidor...`);

    server.close(async () => {
      try {
        await db.pool.end();
      } catch (err) {
        console.error(`[iam] Error cerrando el pool: ${err.message}`);
      }
      process.exit(0);
    });

    // Cierre forzado si alguna conexión queda colgada.
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main();
