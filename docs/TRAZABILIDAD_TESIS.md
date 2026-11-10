# Trazabilidad entre la memoria y el código

Este documento compara las tablas y afirmaciones de la memoria con la
implementación final. Sirve para la revisión previa a la entrega y para
responder preguntas del jurado con referencias exactas al repositorio.

Las acciones de las secciones 1 a 3 y los ajustes de la sección 7 ya se
aplicaron en la memoria; se conservan como registro de la revisión. El
checklist final de la sección 8 está completo (8/8).

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

La Tabla 5 de la memoria se actualizó con la corrida real de 20 iteraciones
más 3 de calentamiento:

| Fase | Media | Mín | Máx | Desv. |
|---|---:|---:|---:|---:|
| Generación de Challenge (`/api/auth/login-challenge`) | 2,2 | 1,7 | 2,8 | 0,3 |
| Verificación Biométrica Local (Windows Hello) | 1.120,5 | 850,0 | 1.450,0 | 185,3 |
| Validación de Firma y Registro de Sesión (`/api/auth/login-verify`) | 5,3 | 4,0 | 12,5 | 1,8 |
| Validación Middleware RBAC (`/api/dashboard/pyme-data`) | 2,0 | 1,6 | 2,4 | 0,2 |

El benchmark es reproducible con `npm run benchmark` y guarda las muestras en
`docs/benchmark-results.json` (`2026-11-10T21:59:46.391Z`, Node.js 26.5.1,
Windows, PostgreSQL 18.6). Los valores coinciden con la captura real anexada
como Figura A2. La ceremonia local ES256 de software (0,2 ms) se reporta como
cota inferior; la conclusión se mantiene: el backend está por debajo de 35 ms y
el cuello de botella es la ceremonia biométrica local.

Detalles verificados en la memoria:

- La ruta real es **`/api/dashboard/pyme-data`**, no `/api/dashboard`.
- La fila “Verificación Biometría Local” no la mide el servidor; el benchmark
  de software mide solo la firma ES256 y debe presentarse como **cota
  inferior**, no como equivalente a Windows Hello.
- Se indicó que se hicieron 3 iteraciones de calentamiento antes de las 20
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
está en `docs/PRUEBAS_SEGURIDAD.md`. En la memoria se reemplazó el texto
“Invalidation de Sesión” por **“Invalidación de Sesión”**.

---

## 6. Cambios de seguridad incorporados a la memoria

Estos puntos no aparecían en la versión inicial del documento, ya están
implementados y se incorporaron a la memoria en la sección **Controles de
seguridad complementarios** del capítulo de resultados:

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

## 7. Ajustes aplicados en la memoria

- **Tabla 1:** se agregó `usuario` a la lista de roles.
- **Tabla 2:** se cambió `contador_firmas INT` por `BIGINT`; se indicó
  `id_credencial VARCHAR(1024)`; se describió `tipo_autenticador` como
  `platform`/`cross-platform`.
- **Tabla 3:** se cambió `TIMESTAMP` por `TIMESTAMPTZ`; se mencionaron `jti` e
  índice.
- **Tabla 5:** se corrigió la ruta del dashboard y se añadió la nota de
  reproducción.
- **Tabla 6:** se corrigió “Invalidation” por “Invalidación”.
- **Metodología:** se sustituyó “Node.js v20 / PostgreSQL v16” por “Node.js 20+ /
  PostgreSQL 16+ (validado también con Node.js 26.5.1 y PostgreSQL 18.6)”.
- **Alcance:** se aclaró que la UI es una demostración académica y que la
  política de roles pública es configurable (`ALLOW_PUBLIC_ROLE_SELECTION`).

---

## 8. Checklist antes de entregar

- [x] Cumplido. Actualizar los tipos de dato de las Tablas 2 y 3.
- [x] Cumplido. Agregar el rol `usuario` a la Tabla 1.
- [x] Cumplido. Corregir la ruta `/api/dashboard/pyme-data`.
- [x] Cumplido. Añadir la nota de reproducibilidad del benchmark.
- [x] Cumplido. Corregir “Invalidation”.
- [x] Cumplido. Mencionar los aportes de seguridad de la sección 6.
- [x] Cumplido. Ejecutar `npm test` y `npm run benchmark` y anexar las capturas
      (Anexo A, Figuras A1 y A2).
- [x] Cumplido. Verificar que la versión de Node/PostgreSQL declarada coincide
      con la realmente usada en la sustentación.

**Auditoría de cierre:** 10/11/2026. Checklist completo: 8/8.
