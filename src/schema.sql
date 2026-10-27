-- ============================================================
-- Sistema Centralizado de Identidad y Accesos (IAM) + WebAuthn
-- PostgreSQL 16+ (compatible con 18)
--
-- Se ejecuta automáticamente al arrancar (src/server.js) y también puede
-- aplicarse manualmente:
--   psql "$DATABASE_URL" -f src/schema.sql
--
-- El script es IDEMPOTENTE: crea tablas/índices si no existen y aplica
-- migraciones de tipo de dato sin destruir información.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Tabla 1: identidades del IAM (sin contraseñas ni hashes)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email           VARCHAR(255) UNIQUE NOT NULL,
  nombre_completo VARCHAR(255) NOT NULL,
  rol             VARCHAR(50) NOT NULL DEFAULT 'usuario',
  estado          BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------------
-- Tabla 2: credenciales FIDO2/WebAuthn (passkeys)
-- Un usuario puede tener N autenticadores (Windows Hello + YubiKey + móvil).
--
-- id_credencial: VARCHAR(1024) porque la especificación WebAuthn permite
--                IDs de credencial de hasta 1023 bytes (base64url ~1365).
-- contador_firmas: BIGINT porque el signature counter es uint32 (hasta
--                4.294.967.295) y PostgreSQL INTEGER solo llega a 2^31-1.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credenciales_webauthn (
  id_credencial      VARCHAR(1024) PRIMARY KEY,
  id_usuario         UUID NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  llave_publica      TEXT NOT NULL,
  contador_firmas    BIGINT NOT NULL DEFAULT 0,
  tipo_autenticador  VARCHAR(100)
);

-- ---------------------------------------------------------------------------
-- Tabla 3: sesiones activas del IAM (JWT emitidos tras login WebAuthn)
--
-- fecha_expiracion: TIMESTAMPTZ (instante absoluto). Antes era TIMESTAMP sin
-- zona y el código tenía que "fabricar" hora UTC; ahora PostgreSQL guarda el
-- instante y las comparaciones con NOW() son correctas en cualquier zona.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sesiones_iam (
  id_sesion         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  id_usuario        UUID NOT NULL REFERENCES usuarios(id_usuario) ON DELETE CASCADE,
  token_jwt         TEXT NOT NULL,
  fecha_expiracion  TIMESTAMPTZ NOT NULL
);

-- ---------------------------------------------------------------------------
-- Migraciones idempotentes para bases de datos ya creadas
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  -- contador_firmas: INTEGER -> BIGINT (uint32 de WebAuthn)
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'credenciales_webauthn'
       AND column_name = 'contador_firmas'
       AND data_type = 'integer'
  ) THEN
    ALTER TABLE credenciales_webauthn
      ALTER COLUMN contador_firmas TYPE BIGINT;
  END IF;

  -- id_credencial: ampliar a VARCHAR(1024)
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'credenciales_webauthn'
       AND column_name = 'id_credencial'
       AND character_maximum_length IS NOT NULL
       AND character_maximum_length < 1024
  ) THEN
    ALTER TABLE credenciales_webauthn
      ALTER COLUMN id_credencial TYPE VARCHAR(1024);
  END IF;

  -- fecha_expiracion: TIMESTAMP -> TIMESTAMPTZ interpretando lo ya guardado
  -- como UTC (que es lo que escribía la versión anterior del backend).
  IF EXISTS (
    SELECT 1
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'sesiones_iam'
       AND column_name = 'fecha_expiracion'
       AND data_type = 'timestamp without time zone'
  ) THEN
    ALTER TABLE sesiones_iam
      ALTER COLUMN fecha_expiracion TYPE TIMESTAMPTZ
      USING fecha_expiracion AT TIME ZONE 'UTC';
  END IF;
END $$;

-- Normaliza emails históricos para que la búsqueda sea insensible a mayúsculas.
UPDATE usuarios
   SET email = lower(trim(email))
 WHERE email <> lower(trim(email));

-- Restricción de roles válidos (Tabla 1). Se agrega una sola vez.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'usuarios_rol_check'
  ) THEN
    ALTER TABLE usuarios
      ADD CONSTRAINT usuarios_rol_check
      CHECK (rol IN ('usuario', 'operativo', 'gerencia', 'admin'));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Índices
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_credenciales_usuario
  ON credenciales_webauthn(id_usuario);

CREATE INDEX IF NOT EXISTS idx_sesiones_usuario
  ON sesiones_iam(id_usuario);

-- Limpieza de sesiones vencidas y filtro del middleware.
CREATE INDEX IF NOT EXISTS idx_sesiones_expiracion
  ON sesiones_iam(fecha_expiracion);

-- Unicidad del token (defensa en profundidad + compatibilidad con tokens
-- antiguos que no llevan claim `jti`).
CREATE UNIQUE INDEX IF NOT EXISTS idx_sesiones_token
  ON sesiones_iam(token_jwt);

-- Email único sin distinguir mayúsculas/minúsculas.
CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_email_lower
  ON usuarios(lower(email));
