const { Pool } = require('pg');
require('dotenv').config();

// Pool de conexiones a PostgreSQL.
// DATABASE_URL ejemplo: postgres://postgres:postgres@localhost:5432/iam_webauthn
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Manejo de errores inesperados del pool (por ejemplo, caída de PostgreSQL).
// El arranque no se tumba aquí: /api/health reporta el estado de la BD.
pool.on('error', (err) => {
  console.error('[db] Error inesperado en el pool:', err.message);
});

module.exports = {
  // query(text, params) -> { rows, rowCount, ... }
  query: (text, params) => pool.query(text, params),
  pool,
};
