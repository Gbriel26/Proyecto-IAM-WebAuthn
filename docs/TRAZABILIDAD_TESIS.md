# Trazabilidad entre la memoria y el código

Este documento compara las tablas y afirmaciones de la memoria con la
implementación final. Sirve para la revisión previa a la entrega y para
responder preguntas del jurado con referencias exactas al repositorio.

---

## 1. Tabla 1 — `usuarios`

| Campo en la memoria | Implementación real | Acción sugerida |
|---|---|---|
| `id_usuario UUID (PK)` | `UUID PRIMARY KEY DEFAULT gen_random_uuid()` | Sin cambios |
| `email VARCHAR (Unique)` | `VARCHAR(255) UNIQUE NOT NULL` + índice único sobre `lower(email)` | Indicar que la comparación es insensible a mayúsculas |
| `nombre_completo VARCHAR` | `VARCHAR(255) NOT NULL` | Sin cambios |
| `rol VARCHAR` | `VARCHAR(50) NOT NULL DEFAULT 'usuario'` + `CHECK` de roles | Añadir el rol **`usuario`** (existe en el código y en la UI) |
| `estado BOOLEAN` | `BOOLEAN NOT NULL DEFAULT TRUE` | Sin cambios |

**Roles implementados:** `usuario`, `operativo`, `gerencia`, `admin`.
La memoria menciona Admin, Operativo y Gerencia; falta el rol base `usuario`
que aparece en el selector de la interfaz.

---

## 2. Tabla 2 — `credenciales_webauthn`

| Campo en la memoria | Implementación real | Acción sugerida |
|---|---|---|
| `id_credencial VARCHAR (PK)` | `VARCHAR(1024) PRIMARY KEY` | Cambiar a **VARCHAR(1024)**; la especificación WebAuthn permite IDs de hasta 1023 bytes |
| `id_usuario UUID (FK)` | `UUID NOT NULL REFERENCES usuarios(...) ON DELETE CASCADE` | Sin cambios |
| `llave_publica TEXT` | `TEXT NOT NULL` (base64url de la COSE key) | Aclarar que se guarda en base64url |
| `contador_firmas INT` | **`BIGINT NOT NULL DEFAULT 0`** | Cambiar a **BIGINT**: el counter es `uint32` y desborda `INTEGER` |
| `tipo_autenticador VARCHAR` | `VARCHAR(100)`: `platform`, `cross-platform` o `desconocido` | Aclarar que identifica la **attachment** (TPM/Windows Hello vs. YubiKey), no la modalidad biométrica/PIN |

La ausencia de `authenticatorAttachment` en las opciones de registro es
intencional: permite registrar tanto autenticadores de plataforma como llaves
externas. Si la memoria afirma que se restringe a `platform`, esa frase debe
actualizarse.

---

## 3. Tabla 3 — `sesiones_iam`

| Campo en la memoria | Implementación real | Acción sugerida |
|---|---|---|
| `id_sesion UUID (PK)` | `UUID PRIMARY KEY DEFAULT gen_random_uuid()` | Sin cambios |
| `id_usuario UUID (FK)` | `UUID NOT NULL REFERENCES usuarios(...) ON DELETE CASCADE` | Sin cambios |
| `token_jwt TEXT` | `TEXT NOT NULL` + índice único | Aclarar que el claim `jti` es igual a `id_sesion` y que la validación usa la PK |
| `fecha_expiracion TIMESTAMP` | **`TIMESTAMPTZ NOT NULL`** | Cambiar a **TIMESTAMPTZ** (instante absoluto, comparaciones correctas con `NOW()`) |

El middleware **no** compara el token completo contra toda la tabla: valida la
firma y luego busca la sesión por `jti` (clave primaria), además de comprobar
`fecha_expiracion > NOW()` y `usuarios.estado = TRUE`.

---

## 4. Tabla 5 — Métricas de latencia

La memoria reporta 20 iteraciones con estos valores:

| Fase (memoria) | Media | Mín | Máx | Desv. |
|---|---:|---:|---:|---:|
| Generación de Challenge (`/api/auth/login-challenge`) | 18,4 | 12,1 | 28,6 | 4,2 |
| Verificación Biométrica Local (Windows Hello) | 1.120,5 | 850,0 | 1.450,0 | 185,3 |
| Validación de Firma y Registro de Sesión (`/api/auth/login-verify`) | 32,1 | 22,4 | 48,9 | 6,8 |
| Validación Middleware RBAC (`/api/dashboard`) | 8,2 | 5,1 | 14,3 | 2,1 |

El repositorio incorpora un benchmark reproducible (`npm run benchmark`) que
mide 20 iteraciones + 3 de calentamiento y guarda las muestras en
`docs/benchmark-results.json`. En la máquina de prueba (Node 26, Windows,
PostgreSQL 18) los valores del backend son aún menores:

| Fase (código actual) | Media | Mín | Máx | Desv. |
|---|---:|---:|---:|---:|
| `/api/auth/login-challenge` | 2,5 | 1,8 | 3,4 | 0,5 |
| Ceremonia local ES256 (software, cota inferior) | 0,2 | 0,1 | 0,4 | 0,1 |
| `/api/auth/login-verify` | 5,8 | 4,4 | 8,2 | 1,2 |
| `/api/dashboard/pyme-data` | 2,4 | 1,7 | 3,4 | 0,6 |

**Recomendación:** conservar la Tabla 5 de la memoria y añadir una nota al pie
con la reproducción actual, o reemplazarla por la nueva medición indicando
hardware y fecha. En ambos casos se mantiene la conclusión: el backend está
por debajo de 35 ms y el cuello de botella es la ceremonia biométrica local.

Detalles a corregir en la memoria:

- La ruta real es **`/api/dashboard/pyme-data`**, no `/api/dashboard`.
- La fila “Verificación Biometría Local” no la mide el servidor; el benchmark
  de software mide solo la firma ES256 y debe presentarse como **cota
  inferior**, no como equivalente a Windows Hello.
- Indicar que se hicieron 3 iteraciones de calentamiento antes de las 20
  medidas.

---

## 5. Tabla 6 — Tasa de éxito

Los cuatro criterios de la memoria están cubiertos por la suite automatizada:

| Criterio | Cobertura |
|---|---|
| Autenticación Passwordless exitosa | Registro + login + RBAC (varios casos) |
| Rechazo sin token (401) | Caso de token ausente |
| Rechazo de tokens expirados/inválidos | Casos de token inválido, expirado y revocado |
| Invalidación tras logout | Logout + reutilización del token (401) |

La suite completa son **24 pruebas** (`npm test`), todas exitosas. El detalle
está en `docs/PRUEBAS_SEGURIDAD.md`. Se sugiere reemplazar el texto
“Invalidation de Sesión” por **“Invalidación de Sesión”**.

---

## 6. Cambios de seguridad que conviene añadir a la memoria

Estos puntos no aparecían en la versión inicial del documento y ahora están
implementados; conviene mencionarlos como aportes de la versión final:

1. **Retos de un solo uso con TTL** (`ChallengeStore`): 5 minutos, máximo
   10.000 entradas y rechazo de replay.
2. **`JWT_SECRET` obligatorio** (mínimo 32 caracteres, sin fallback) y claims
   `iss`, `aud`, `jti`; algoritmo fijado a `HS256`.
3. **Sesión validada por `jti`** (PK) + expiración + estado del usuario, y rol
   leído de PostgreSQL en cada petición.
4. **Anti-enumeración** en `login-challenge` (misma respuesta para email
   inexistente, deshabilitado o sin credenciales) y **rate limiting** por IP y
   ruta.
5. **Protección contra secuestro de cuenta en el alta**: para añadir una llave
   a una cuenta existente se exige sesión de esa cuenta o de un administrador.
6. **El enrolamiento no cambia el rol**: un usuario no puede auto-escalar
   privilegios manipulando el formulario.
7. **Cabeceras de seguridad** (CSP, HSTS en producción, CORS restringido) y
   cookie `httpOnly`/`SameSite=Lax`/`Secure` en producción.
8. **Migraciones idempotentes** del esquema: `BIGINT`, `VARCHAR(1024)`,
   `TIMESTAMPTZ`, normalización de emails, `CHECK` de roles e índices.

---

## 7. Ajustes de redacción sugeridos

- **Tabla 1:** agregar `usuario` a la lista de roles.
- **Tabla 2:** cambiar `contador_firmas INT` por `BIGINT`; indicar
  `id_credencial VARCHAR(1024)`; describir `tipo_autenticador` como
  `platform`/`cross-platform`.
- **Tabla 3:** cambiar `TIMESTAMP` por `TIMESTAMPTZ`; mencionar `jti` e índice.
- **Tabla 5:** corregir la ruta del dashboard y añadir la nota de reproducción.
- **Tabla 6:** corregir “Invalidation” por “Invalidación”.
- **Metodología:** sustituir “Node.js v20 / PostgreSQL v16” por “Node.js 20+ /
  PostgreSQL 16+ (validado también con Node 26 y PostgreSQL 18)”.
- **Alcance:** aclarar que la UI es una demostración académica y que la
  política de roles pública es configurable (`ALLOW_PUBLIC_ROLE_SELECTION`).

---

## 8. Checklist antes de entregar

- [ ] Actualizar los tipos de dato de las Tablas 2 y 3.
- [ ] Agregar el rol `usuario` a la Tabla 1.
- [ ] Corregir la ruta `/api/dashboard/pyme-data`.
- [ ] Añadir la nota de reproducibilidad del benchmark.
- [ ] Corregir “Invalidation”.
- [ ] Mencionar los aportes de seguridad de la sección 6.
- [ ] Ejecutar `npm test` y `npm run benchmark` y anexar las capturas.
- [ ] Verificar que la versión de Node/PostgreSQL declarada coincide con la
      realmente usada en la sustentación.
