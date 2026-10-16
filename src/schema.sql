-- ============================================================
-- Sistema Centralizado de Identidad y Accesos (IAM) + WebAuthn
-- Ejecutar con: psql $DATABASE_URL -f src/schema.sql
-- ============================================================

-- Extensión para generar UUIDs (pgcrypto es estándar en Postgres)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tabla de identidades del IAM
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email           VARCHAR(255) UNIQUE NOT NULL,
  nombre_completo VARCHAR(255) NOT NULL,
  rol             VARCHAR(50) NOT NULL DEFAULT 'usuario',
  estado          BOOLEAN NOT NULL DEFAULT TRUE
);

-- Credenciales FIDO2/WebAuthn (passkeys) asociadas a cada usuario.
-- Un usuario puede tener N autenticadores (laptop + celular + llave USB).
CREATE TABLE IF NOT EXISTS credenciales_webauthn (
  id_credencial      VARCHAR(255) PRIMARY KEY,
  id_usuario         UUID NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  llave_publica      TEXT NOT NULL,
  contador_firmas    INTEGER NOT NULL DEFAULT 0,
  tipo_autenticador  VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_credenciales_usuario
  ON credenciales_webauthn(id_usuario);

-- Sesiones activas del IAM (JWT emitidos tras un login WebAuthn válido)
CREATE TABLE IF NOT EXISTS sesiones_iam (
  id_sesion         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  id_usuario        UUID NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  token_jwt         TEXT NOT NULL,
  fecha_expiracion  TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sesiones_usuario
  ON sesiones_iam(id_usuario);
