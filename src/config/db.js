const { Pool } = require('pg');
require('dotenv').config();

// Pool de conexiones a PostgreSQL.
// DATABASE_URL ejemplo: postgres://postgres:postgres@localhost:5432/iam_webauthn
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Verificación temprana de conectividad (no tumba el proceso si falla,
// solo lo reporta para facilitar el diagnóstico en la universidad).
pool.on('error', (err) => {
  console.error('[db] Error inesperado en el pool:', err.message);
});

module.exports = {
  // query(text, params) -> { rows, rowCount, ... }
  query: (text, params) => pool.query(text, params),
  pool,
};
