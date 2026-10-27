# IAM Passwordless para PyMEs — WebAuthn / FIDO2

Middleware centralizado de **Gestión de Identidades y Accesos (IAM)** con
autenticación **sin contraseñas** basada en **WebAuthn / FIDO2**, JWT y RBAC.
Proyecto de tesis — Corporación Universitaria Latinoamericana (CUL),
ZISXA-Proyecto II 26-2.

> Sustituye las contraseñas por criptografía asimétrica: la llave privada
> permanece en el autenticador (TPM 2.0 / Windows Hello o llave USB) y el
> servidor solo guarda la llave pública.

---

## 1. Arquitectura

```
┌──────────────────────────────┐        ┌──────────────────────────────┐
│  Navegador (cliente)         │        │  Servidor IAM (Node/Express) │
│  public/                     │        │  src/                        │
│                              │        │                              │
│  startRegistration() ────────┼───────▶│  /register-challenge         │
│  Windows Hello / YubiKey     │        │   └─ challenge (TTL, 1 uso)  │
│  (llave privada en TPM)      │        │                              │
│  attestation ────────────────┼───────▶│  /register-verify            │
│                              │        │   └─ verifyRegistration      │
│                              │        │      └─ usuarios             │
│  startAuthentication() ──────┼───────▶│      └─ credenciales_webauthn│
│  firma FIDO2 ────────────────┼───────▶│  /login-verify               │
│                              │        │   └─ verifyAuthentication    │
│  Token JWT ──────────────────┼───────▶│      └─ counter anti-clonación│
│  Authorization: Bearer       │        │      └─ sesiones_iam + JWT   │
│                              │        │                              │
│  Panel protegido ────────────┼───────▶│  /api/dashboard/pyme-data    │
└──────────────────────────────┘        │   └─ requireAuth + RBAC      │
                                        └──────────────┬───────────────┘
                                                       │
                                                PostgreSQL 16+
```

**Tablas** (`src/schema.sql`):

| Tabla | Propósito |
|---|---|
| `usuarios` | Identidad, email, nombre, rol y estado (sin contraseñas) |
| `credenciales_webauthn` | Llave pública, contador de firmas y tipo de autenticador |
| `sesiones_iam` | JWT emitidos, usuario y fecha de expiración (revocación) |

---

## 2. Requisitos

- Node.js **20+**
- PostgreSQL **16+** (probado también con 18)
- Navegador con WebAuthn: Chrome/Edge, Windows Hello con TPM 2.0, Touch ID
  o una llave USB FIDO2 (YubiKey)

---

## 3. Instalación

```bash
# 1. Dependencias
npm install

# 2. Base de datos
createdb iam_webauthn

# 3. Configuración
copy .env.example .env        # Windows
# cp .env.example .env        # Linux/macOS

# 4. Genera un JWT_SECRET real y pégalo en .env
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"

# 5. Aplica el esquema (también se aplica solo al arrancar)
npm run db:init

# 6. Arranca
npm run dev
```

Abre `http://localhost:3000`.

> **Importante:** `RP_ID` debe coincidir con el dominio real. En local es
> `localhost`. Si pruebas desde otro equipo de la red, WebAuthn exige HTTPS
> (o `localhost`); no uses una IP plana.

---

## 4. Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/auth/register-challenge` | Genera el reto de registro (attestation) |
| `POST` | `/api/auth/register-verify` | Verifica la attestation y guarda la llave pública |
| `POST` | `/api/auth/login-challenge` | Genera el reto de login (assertion) |
| `POST` | `/api/auth/login-verify` | Verifica la firma, actualiza el counter y emite el JWT |
| `POST` | `/api/auth/logout` | Revoca la sesión en PostgreSQL y limpia la cookie |
| `GET` | `/api/dashboard/pyme-data` | Ruta protegida con JWT + RBAC |
| `GET` | `/api/health` | Estado del servidor y de la base de datos |

El token se acepta como `Authorization: Bearer <token>` o en la cookie
httpOnly `iam_token`.

---

## 5. Decisiones de seguridad implementadas

### 5.1 Autenticadores de plataforma y externos

Se eliminó `authenticatorAttachment: 'platform'` de las opciones de registro.
Así el navegador acepta tanto **Windows Hello / TPM 2.0 / Touch ID**
(`platform`) como **llaves USB/NFC** (`cross-platform`, p. ej. YubiKey),
alineado con la Tabla 2 de la tesis. El tipo se guarda en
`credenciales_webauthn.tipo_autenticador`.

### 5.2 Contador de firmas `BIGINT`

El *signature counter* de WebAuthn es un `uint32` (hasta 4.294.967.295) y
`INTEGER` de PostgreSQL solo llega a 2.147.483.647. Se migró a `BIGINT` y se
amplió `id_credencial` a `VARCHAR(1024)` (la especificación permite IDs de
hasta 1023 bytes).

### 5.3 Retos de un solo uso con TTL

Los `Map` eternos se sustituyeron por `ChallengeStore` (`src/utils/challengeStore.js`):
TTL de 5 minutos, límite de 10.000 entradas, barrido periódico y `consume()`
de un solo uso. Un challenge reutilizado se rechaza.

### 5.4 JWT endurecido

- `JWT_SECRET` es obligatorio (mínimo 32 caracteres): la app **no arranca**
  sin él. Se eliminó el fallback `'dev-secret'`.
- Claims `iss`, `aud` y `jti`; algoritmo fijado a `HS256`.
- `jti` = `id_sesion`. El middleware busca la sesión por la **clave primaria**
  (no por el token completo), evitando escaneos secuenciales.
- El rol se lee de PostgreSQL en cada petición: una degradación de privilegios
  se aplica de inmediato.
- Se validan expiración de la sesión, estado del usuario y revocación.

### 5.5 Anti-enumeración y rate limiting

- `login-challenge` responde igual para email inexistente, deshabilitado o sin
  passkeys: `404` con el mismo mensaje.
- Rate limiter en memoria por IP + ruta: límite general y límite estricto para
  las ceremonias WebAuthn (`429` + `Retry-After`).

### 5.6 Protección contra secuestro de cuenta en el alta

Un usuario **nuevo** puede registrarse públicamente. Para añadir otra passkey
a una cuenta **existente** se exige:

- una sesión válida de esa misma cuenta, o
- una sesión de administrador.

Sin esta regla, cualquiera que conociera el email de un empleado podría
registrar su propio autenticador en esa cuenta y luego iniciar sesión como él.

Además, el enrolamiento de una llave **nunca cambia el rol** de una cuenta
existente: un usuario no puede auto-escalar privilegios manipulando el
formulario, y un administrador no degrada a un empleado por accidente. Los
cambios de rol deben ser una acción administrativa explícita y auditada.

### 5.7 Endurecimiento HTTP

- Cabeceras `CSP`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy` y `HSTS` en producción.
- CORS restringido a los orígenes de `ORIGIN`.
- Cookie `httpOnly`, `SameSite=Lax` y `Secure` en producción.
- `X-Request-Id` para trazabilidad y errores 500 sin filtrar detalles internos.

### 5.8 Esquema y migraciones

`src/schema.sql` es idempotente y migra bases existentes:

- `contador_firmas`: `INTEGER` → `BIGINT`
- `id_credencial`: `VARCHAR(255)` → `VARCHAR(1024)`
- `fecha_expiracion`: `TIMESTAMP` → `TIMESTAMPTZ`
- normalización de emails a minúsculas
- restricción `CHECK` de roles
- índices únicos de token/email e índice de expiración

---

## 6. Pruebas automatizadas

```bash
npm test
```

**24 pruebas** con `node:test`, sin dependencias extra. Incluyen un
**autenticador WebAuthn de software** (`tools/softwareAuthenticator.js`) que
genera claves P-256 y firmas ES256 reales, por lo que se ejecuta el flujo
completo contra PostgreSQL sin navegador.

Cobertura principal:

- registro + login + JWT + RBAC + logout con revocación
- segundo autenticador `cross-platform` (YubiKey)
- rechazo de replay de challenge
- rechazo de assertion con origin ajeno (anti-phishing)
- rechazo de counter que retrocede (anti-clonación)
- credencial vinculada a una segunda cuenta
- token ausente, inválido, expirado y revocado
- usuario deshabilitado
- RBAC por rol (`admin`, `gerencia`, `operativo`)
- roles/emails inválidos y manipulación de rol entre challenge y verify
- secuestro de cuenta en el alta y auto-escalada de rol
- rate limiting
- TTL y single-use del `ChallengeStore`
- política de roles (`ALLOW_PUBLIC_ROLE_SELECTION=false`)

Detalle y matriz de pruebas: [`docs/PRUEBAS_SEGURIDAD.md`](docs/PRUEBAS_SEGURIDAD.md).

Trazabilidad con las tablas de la memoria y ajustes de redacción:
[`docs/TRAZABILIDAD_TESIS.md`](docs/TRAZABILIDAD_TESIS.md).

---

## 7. Benchmark reproducible

```bash
npm run benchmark
# o con más iteraciones:
BENCH_ITERATIONS=50 npm run benchmark
```

Genera `docs/benchmark-results.json` y una tabla por consola. Ejemplo de
ejecución local (Node 26, Windows, PostgreSQL 18):

| Fase | Media (ms) | Mín (ms) | Máx (ms) | Desv. estándar (ms) |
|---|---:|---:|---:|---:|
| Generación de Challenge (`/api/auth/login-challenge`) | 2,5 | 1,8 | 3,4 | 0,5 |
| Ceremonia local ES256 (software, cota inferior) | 0,2 | 0,1 | 0,4 | 0,1 |
| Validación de Firma + JWT + Sesión (`/api/auth/login-verify`) | 5,8 | 4,4 | 8,2 | 1,2 |
| Validación Middleware RBAC (`/api/dashboard/pyme-data`) | 2,4 | 1,7 | 3,4 | 0,6 |

> La ceremonia real con Windows Hello/TPM añade la interacción biométrica
> humana (~1 s), que no es medible desde el servidor. El benchmark aísla el
> backend y sirve como cota inferior reproducible. Los valores pueden variar
> según el hardware; la conclusión de la tesis (< 35 ms en backend) se
> mantiene.

---

## 8. Estructura del proyecto

```
src/
  app.js                     Express, CORS, cabeceras, errores
  server.js                  Arranque, esquema y cierre ordenado
  config/
    db.js                    Pool de PostgreSQL
    env.js                   Configuración validada (fail-fast)
  controllers/
    auth.controller.js       Registro, login, logout, RBAC
  middleware/
    auth.js                  JWT + sesión + estado + rol vigente
    rateLimit.js             Rate limiting en memoria
  routes/
    auth.routes.js
    dashboard.routes.js
  services/
    tokenService.js          Emisión/verificación de JWT
  utils/
    challengeStore.js        Challenges con TTL y un solo uso
  schema.sql                 Tablas, migraciones e índices
public/                      Frontend HTML/CSS/JS
tests/                       Pruebas de integración y unitarias
tools/                       Autenticador de software y utilidades
scripts/                     db:init y benchmark
docs/                        Resultados y matriz de pruebas
```

---

## 9. Notas para la sustentación

- **¿Dónde está la contraseña?** No existe: la autenticación se basa en un par
  de claves asimétricas. El servidor solo almacena la llave pública.
- **¿Por qué resiste phishing?** El `origin` y el `rpId` se validan en el
  servidor y la firma está ligada al challenge; una página falsa no puede
  producir una assertion válida para el dominio real.
- **¿Cómo se revoca una sesión?** `logout` elimina la fila de `sesiones_iam`;
  el middleware la busca por `jti` y rechaza el token aunque no haya expirado.
- **¿Qué pasa si se clona un autenticador?** El contador de firmas debe
  aumentar; si retrocede o se repite, el servidor rechaza la autenticación.
- **¿Cómo se añade un YubiKey?** El usuario inicia sesión con su llave actual
  y registra la nueva; el servidor exige la sesión para evitar secuestros.

---

## 10. Limitaciones y trabajo futuro

- Los challenges y el rate limiting viven en memoria: para varias instancias
  se recomienda Redis.
- El almacenamiento del JWT en `sesiones_iam` conserva el token completo por
  trazabilidad académica; en producción se puede guardar solo su hash
  `SHA-256` para que un volcado de BD no permita reutilizar sesiones.
- El alta pública distingue entre un email nuevo (`200`) y uno existente sin
  sesión (`403`), por lo que puede usarse para enumerar cuentas. En producción
  se recomienda un flujo de invitación o alta exclusivamente administrativa.
- No se implementa attestation con certificado del fabricante
  (`attestationType: 'none'`), suficiente para el alcance de la tesis.
- La UI es una demostración académica; no incluye recuperación de cuenta ni
  enrolamiento corporativo masivo.
