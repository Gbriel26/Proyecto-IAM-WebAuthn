# Matriz de pruebas de seguridad y desempeño

Documento de soporte para la memoria y la sustentación. Describe qué se
prueba, cómo se ejecuta y qué evidencia produce el repositorio.

---

## 1. Cómo ejecutar

```bash
npm test            # 24 pruebas automatizadas (node:test)
npm run benchmark   # 20 iteraciones de latencia + docs/benchmark-results.json
```

Requisitos: PostgreSQL activo, `.env` configurado y `JWT_SECRET` de al menos
32 caracteres. Las pruebas crean usuarios con el prefijo `test+...` y los
eliminan al finalizar (borrado en cascada de credenciales y sesiones).

Resultado de la última ejecución:

- **24 pruebas / 24 exitosas / 0 fallidas**
- Duración total: ~3,4 s (sin contar el arranque de PostgreSQL)
- Entorno: Node.js 26, Windows, PostgreSQL 18 (compatible con 16+)

---

## 2. Pruebas automatizadas

### 2.1 Retos criptográficos (`tests/challengeStore.test.js`)

| # | Caso | Qué demuestra |
|---|---|---|
| 1 | Expiración por TTL | Un challenge viejo no puede usarse |
| 2 | `consume()` de un solo uso | Un challenge no se reutiliza |
| 3 | Cota de entradas | El almacén no crece sin límite (DoS de memoria) |
| 4 | TTL inválido | La configuración falla de forma explícita |

### 2.2 Flujo WebAuthn e IAM (`tests/integration.test.js`)

| # | Caso | Resultado esperado | Objetivo que respalda |
|---|---|---|---|
| 5 | Registro + login + RBAC + logout | 200 y revocación efectiva | Autenticación sin contraseña y sesión JWT |
| 6 | Segundo autenticador `cross-platform` | 200 con dos credenciales | Compatibilidad con YubiKey (Tabla 2) |
| 7 | Añadir llave a cuenta existente sin sesión | 403 | Prevención de secuestro de cuenta |
| 8 | Auto-escalada de rol al añadir llave | Rol se conserva | Integridad del RBAC |
| 9 | Replay del mismo challenge | 400 | Anti-replay |
| 10 | Assertion firmada para otro origin | 401 | Anti-phishing (origin/rpId) |
| 11 | Counter de firmas que retrocede | 401 | Anti-clonación de autenticador |
| 12 | Credencial ya ligada a otra cuenta | 409 | Integridad de identidades |
| 13 | Token ausente / inválido / expirado / revocado | 401 | Gestión segura de sesiones |
| 14 | Usuario deshabilitado | 401 y sin challenge | Ciclo de vida de la identidad |
| 15 | RBAC admin / gerencia / operativo | Módulos distintos | Control de acceso basado en roles |
| 16 | Rol/email/nombre inválidos | 400 | Validación de entrada |
| 17 | Rol alterado entre challenge y verify | Se ignora el body | Integridad del proceso |
| 18 | Misma respuesta para email inexistente/deshabilitado | 404 genérico | Anti-enumeración |
| 19 | Logout idempotente y limpieza de cookie | 200 | Cierre de sesión seguro |

### 2.3 Rate limiting (`tests/rateLimit.test.js`)

| # | Caso | Resultado esperado |
|---|---|---|
| 20 | Tercer intento de `login-challenge` sobre el límite | 429 + `Retry-After` |

### 2.4 Política de roles (`tests/rolePolicy.test.js`)

| # | Caso | Resultado esperado |
|---|---|---|
| 21 | Alta pública con rol `admin` sin sesión | 403 |
| 22 | Alta pública con rol `usuario` | 200 |
| 23 | Admin autenticado asigna `gerencia` | 200 |
| 24 | Token de rol `usuario` intenta asignar `admin` | 403 |

---

## 3. Correspondencia con la Tabla 6 de la tesis

| Criterio de la Tabla 6 | Cobertura en la suite |
|---|---|
| Autenticación Passwordless exitosa | Casos 5, 6, 9, 15 (registro, login y RBAC) |
| Rechazo de peticiones sin token (401) | Caso 13 |
| Rechazo de tokens expirados/inválidos | Caso 13 |
| Invalidación de sesión tras logout | Casos 5 y 19 |

Los cuatro criterios quedan cubiertos y pasan al 100 %. Para reproducir la
tabla con 30/15/10/10 solicitudes, se puede ejecutar el flujo con
`npm run benchmark` (20 logins) y repetir los casos 13 y 19; el resultado
esperado es el mismo.

---

## 4. Pruebas manuales con hardware real

Estas pruebas complementan la suite automática y son las que conviene mostrar
en la sustentación.

### 4.1 Windows Hello / TPM 2.0

1. Abrir `http://localhost:3000` en Edge o Chrome.
2. Registrar un empleado nuevo.
3. Verificar que aparece el diálogo nativo de Windows Hello (huella, rostro o
   PIN) y que la ceremonia termina con `verified: true`.
4. En PostgreSQL:
   ```sql
   SELECT tipo_autenticador, contador_firmas
     FROM credenciales_webauthn
    ORDER BY contador_firmas DESC;
   ```
   Debe aparecer `platform`.
5. Cerrar sesión y volver a entrar: el contador debe incrementarse en cada
   login.

### 4.2 YubiKey / llave USB

1. Iniciar sesión con la llave actual (o registrar el primer usuario).
2. En la pestaña **Autenticación**, escribir el mismo email y registrar otra
   llave; el servidor exige la sesión activa.
3. Insertar la YubiKey y completar el gesto (toque + PIN si está configurado).
4. Verificar en la BD que ahora hay dos filas para el usuario y que la nueva
   tiene `tipo_autenticador = 'cross-platform'`.
5. Cerrar sesión e iniciar con la YubiKey.

### 4.3 Simulación de phishing

1. Servir una copia del frontend en otro origen, por ejemplo
   `http://localhost:5500` (o un dominio de pruebas).
2. Intentar iniciar sesión contra el servidor IAM real.
3. El navegador no ofrece la credencial porque el `rpId` no coincide con el
   origen; si se fuerza una assertion con `origin` falso, el servidor la
   rechaza (caso 10).
4. Conclusión: una página de phishing no puede obtener una firma válida para
   el dominio legítimo, porque la llave privada está ligada al RP ID y el
   servidor valida `clientDataJSON.origin`.

### 4.4 Replay y manipulación de token

1. En DevTools → Network, copiar el body de `login-verify` y reenviarlo.
   Resultado: `400` (challenge consumido).
2. Copiar el JWT y cambiar un carácter; usarlo en
   `GET /api/dashboard/pyme-data`. Resultado: `401`.
3. Hacer logout y reutilizar el token anterior. Resultado: `401`.

### 4.5 Rate limiting

```bash
for ($i=1; $i -le 35; $i++) {
  curl.exe -s -o NUL -w "%{http_code}`n" -X POST http://localhost:3000/api/auth/login-challenge `
    -H "Content-Type: application/json" -d '{\"email\":\"nadie@pyme.com\"}'
}
```

Los primeros intentos devuelven `404` (respuesta genérica) y, al superar el
límite estricto, `429` con `Retry-After`.

### 4.6 Inspección de la base de datos

```sql
-- No debe existir ninguna columna de contraseña o hash
SELECT column_name, data_type
  FROM information_schema.columns
 WHERE table_name = 'usuarios';

-- Solo llaves públicas y contadores
SELECT id_credencial, llave_publica, contador_firmas, tipo_autenticador
  FROM credenciales_webauthn;

-- Sesiones activas y su expiración
SELECT id_sesion, id_usuario, fecha_expiracion
  FROM sesiones_iam
 ORDER BY fecha_expiracion DESC;
```

---

## 5. Resultados de desempeño

Salida de `npm run benchmark` (20 iteraciones + 3 de calentamiento, Node 26,
Windows, PostgreSQL 18):

| Fase | Media (ms) | Mín (ms) | Máx (ms) | Desv. estándar (ms) |
|---|---:|---:|---:|---:|
| Generación de Challenge (`/api/auth/login-challenge`) | 2,5 | 1,8 | 3,4 | 0,5 |
| Ceremonia local ES256 (software, cota inferior) | 0,2 | 0,1 | 0,4 | 0,1 |
| Validación de Firma + JWT + Sesión (`/api/auth/login-verify`) | 5,8 | 4,4 | 8,2 | 1,2 |
| Validación Middleware RBAC (`/api/dashboard/pyme-data`) | 2,4 | 1,7 | 3,4 | 0,6 |

**Interpretación:** toda la latencia imputable al backend y a PostgreSQL se
mantiene muy por debajo de los 35 ms. La diferencia con la Tabla 5 de la
memoria se explica por el hardware y por medir la firma de software en lugar
de la interacción biométrica real (~1 s). Ambas mediciones son compatibles con
la conclusión: el cuello de botella es la ceremonia local del usuario, no el
servidor.

El archivo `docs/benchmark-results.json` conserva las muestras individuales
para anexarlas como evidencia.

---

## 6. Evidencia sugerida para el documento

- Captura de `npm test` con **24/24**.
- Captura del diálogo de Windows Hello.
- Captura de la tabla `credenciales_webauthn` con una credencial `platform` y
  otra `cross-platform`.
- Captura de la consola de auditoría del frontend (challenge → firma →
  verificación → JWT).
- Captura de `npm run benchmark` y del JSON generado.
- Captura de un `401` al reutilizar un token después del logout y de un `400`
  al repetir un challenge.
