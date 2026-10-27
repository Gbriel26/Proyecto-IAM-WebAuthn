'use strict';

/**
 * Aplica src/schema.sql (creación + migraciones idempotentes).
 * Uso: npm run db:init
 */
const fs = require('fs');
const path = require('path');

require('dotenv').config();
const db = require('../src/config/db');

(async () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'src', 'schema.sql'), 'utf8');
  await db.query(sql);
  console.log('[iam] Esquema aplicado correctamente.');
  await db.pool.end();
})().catch((err) => {
  console.error('[iam] Error aplicando el esquema:', err.message);
  process.exit(1);
});
