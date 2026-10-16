require('dotenv').config();
const fs = require('fs');
const path = require('path');
const app = require('./app');
const db = require('./config/db');

const PORT = process.env.PORT || 3000;

async function initDb() {
  // Crea las tablas automáticamente a partir de src/schema.sql
  // para que la demo funcione con solo `npm run dev`.
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await db.query(sql);
  console.log('[iam] Esquema verificado (usuarios, credenciales_webauthn, sesiones_iam)');
}

initDb()
  .catch((err) => {
    console.error('[iam] No se pudo inicializar la BD. ¿DATABASE_URL correcta y Postgres activo?');
    console.error(err.message);
  })
  .finally(() => {
    app.listen(PORT, () => {
      console.log(`[iam] Servidor IAM escuchando en ${process.env.ORIGIN || `http://localhost:${PORT}`}`);
      console.log(`[iam] RP_ID=${process.env.RP_ID} RP_NAME=${process.env.RP_NAME}`);
    });
  });
