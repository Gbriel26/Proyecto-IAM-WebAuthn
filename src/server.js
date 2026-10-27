'use strict';

const fs = require('fs');
const path = require('path');

// Valida la configuración antes de arrancar (lanza si falta JWT_SECRET, etc.).
const config = require('./config/env');
const app = require('./app');
const db = require('./config/db');

async function initDb() {
  // Crea/migra las tablas a partir de src/schema.sql (idempotente).
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await db.query(sql);
  console.log('[iam] Esquema verificado (usuarios, credenciales_webauthn, sesiones_iam)');
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

  const server = app.listen(config.port, () => {
    console.log(`[iam] Servidor IAM escuchando en ${config.primaryOrigin} (puerto ${config.port})`);
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
