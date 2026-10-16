// Frontend IAM + WebAuthn — lógica modular por pestañas.
// Habla con /api/auth y /api/dashboard, y con el autenticador vía
// @simplewebauthn/browser. Terminología oficial de tesis:
// "Reto Criptográfico (Challenge)", "Firma Digital FIDO2",
// "Token JWT de Acceso Unificado" y "Verificación en Servidor IAM".
import {
  startRegistration,
  startAuthentication,
} from 'https://esm.sh/@simplewebauthn/browser@13.1.2';

// ---------------------------------------------------------------- estado
const state = { user: null, token: null, tokenVisible: false };

// ---------------------------------------------------------- utilidades UI
const $ = (id) => document.getElementById(id);

function audit(msg, type = 'info') {
  const box = $('audit-log');
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.innerHTML = `<span class="t">[${time}]</span> <span class="${type}"></span>`;
  line.querySelector('span:last-child').textContent = msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

// Sistema de pestañas principales: conmutación por data-tab.
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    $(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

function goTab(name) {
  document.querySelector(`[data-tab="${name}"]`)?.click();
}

// Sub-pestañas de Autenticación: Alta de Empleado vs Acceso Corporativo.
function setAuthMode(mode) {
  const isRegister = mode === 'register';
  $('mode-register-btn').classList.toggle('active', isRegister);
  $('mode-login-btn').classList.toggle('active', !isRegister);
  $('auth-mode-register').hidden = !isRegister;
  $('auth-mode-login').hidden = isRegister;
}
$('mode-register-btn').addEventListener('click', () => setAuthMode('register'));
$('mode-login-btn').addEventListener('click', () => setAuthMode('login'));

async function postJSON(url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(url, {
    method: 'POST',
    headers,
    credentials: 'include',
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

// ------------------------------------------------------- panel protegido
// El Token JWT de Acceso Unificado se muestra enmascarado por defecto
// (solo primer y último tramo) para no exponerlo en pantalla o capturas.
function maskToken(token) {
  if (!token || token.length < 20) return token;
  return `${token.slice(0, 8)}...••••••••...${token.slice(-6)}`;
}

function renderDashboard() {
  const active = Boolean(state.token && state.user);
  $('session-dot').classList.toggle('on', active);
  $('session-status').textContent = active
    ? 'Sesión IAM activa (Token JWT de Acceso Unificado válido)'
    : 'Sin sesión activa';
  $('dash-user').textContent = state.user?.nombre_completo ?? '—';
  $('dash-email').textContent = state.user?.email ?? '—';
  $('dash-rol').textContent = state.user?.rol ?? '—';
  $('dash-token').textContent = !state.token
    ? 'Aún no hay token. Inicia sesión en la pestaña Autenticación.'
    : (state.tokenVisible ? state.token : maskToken(state.token));
  $('btn-toggle-token').disabled = !active;
  $('btn-toggle-token').textContent = state.tokenVisible ? 'Ocultar token' : 'Mostrar token';
  $('btn-copy-token').disabled = !active;
}

// Alterna entre vista enmascarada y token completo.
$('btn-toggle-token').addEventListener('click', () => {
  if (!state.token) return;
  state.tokenVisible = !state.tokenVisible;
  renderDashboard();
});

// Copia el token COMPLETO al portapapeles (aunque esté enmascarado en vista).
$('btn-copy-token').addEventListener('click', async () => {
  if (!state.token) return;
  try {
    await navigator.clipboard.writeText(state.token);
    audit('Token JWT de Acceso Unificado copiado al portapapeles.', 'ok');
  } catch {
    audit('No se pudo copiar automáticamente: selecciona el token con "Mostrar token".', 'err');
  }
});

function renderModules(data) {
  const box = $('dash-modules');
  box.innerHTML = '';
  if (!data?.modulos?.length) {
    box.innerHTML = '<p class="hint">Sin módulos para este rol.</p>';
    return;
  }
  const level = document.createElement('p');
  level.className = 'hint';
  level.innerHTML = `Nivel de acceso: <span class="level">${data.nivel_acceso} (${data.rol})</span>`;
  box.appendChild(level);
  data.modulos.forEach((m) => {
    const div = document.createElement('div');
    div.className = 'module';
    const b = document.createElement('b');
    b.textContent = m.nombre;
    const s = document.createElement('span');
    s.textContent = m.descripcion;
    div.append(b, s);
    box.appendChild(div);
  });
}

/** Consulta la ruta protegida con el Token JWT de Acceso Unificado. */
async function loadPymeData() {
  if (!state.token) {
    $('dash-modules').innerHTML = '<p class="hint">Sin datos. Inicia sesión para consultar /api/dashboard/pyme-data.</p>';
    return;
  }
  try {
    audit('Panel: solicitando módulos PyME con Token JWT de Acceso Unificado…');
    const r = await fetch('/api/dashboard/pyme-data', {
      headers: { Authorization: `Bearer ${state.token}` },
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    renderModules(data);
    audit(`Panel: ${data.modulos.length} módulo(s) habilitados (rol ${data.rol}, nivel ${data.nivel_acceso}).`, 'ok');
  } catch (err) {
    audit(`Panel: no se pudo cargar pyme-data: ${err.message}`, 'err');
  }
}

$('btn-refresh-modules').addEventListener('click', loadPymeData);

// Cierre de sesión REAL: invalida la sesión en PostgreSQL (sesiones_iam).
$('btn-logout').addEventListener('click', async () => {
  try {
    if (state.token) await postJSON('/api/auth/logout', {}, state.token);
  } catch (err) {
    audit(`Cierre de sesión: aviso del servidor: ${err.message}`, 'err');
  }
  state.user = null;
  state.token = null;
  state.tokenVisible = false;
  renderDashboard();
  $('dash-modules').innerHTML = '<p class="hint">Sin datos. Inicia sesión para consultar /api/dashboard/pyme-data.</p>';
  audit('Sesión IAM cerrada: Token JWT de Acceso Unificado invalidado en PostgreSQL.');
});

$('btn-clear-log').addEventListener('click', () => { $('audit-log').innerHTML = ''; });

// -------------------------------------------------------------- registro
// 1. Reto Criptográfico (Challenge) del Servidor IAM → 2. startRegistration
// (crea el par de claves; la privada no sale del dispositivo) →
// 3. Verificación en Servidor IAM y guardado de la llave pública.
$('btn-register').addEventListener('click', async () => {
  const email = $('reg-email').value.trim();
  const nombre_completo = $('reg-nombre').value.trim();
  const rol = $('reg-rol').value;
  if (!email) return audit('Alta de Empleado: ingresa un email.', 'err');
  try {
    audit(`Alta de Empleado: solicitando Reto Criptográfico (Challenge) para ${email} (rol ${rol})…`);
    const optionsJSON = await postJSON('/api/auth/register-challenge', { email, nombre_completo, rol });
    audit('Alta de Empleado: Reto Criptográfico (Challenge) recibido. Esperando gesto biométrico…');
    const attResp = await startRegistration({ optionsJSON });
    audit('Alta de Empleado: credencial creada. Enviando a Verificación en Servidor IAM…');
    const result = await postJSON('/api/auth/register-verify', { email, nombre_completo, rol, attResp });
    audit(`Alta de Empleado OK: credencial FIDO2 guardada para ${result.user.email} (rol ${result.user.rol}).`, 'ok');
    goTab('audit');
  } catch (err) {
    audit(`Alta de Empleado fallida: ${err.message}`, 'err');
  }
});

// ----------------------------------------------------------------- login
// 1. Reto Criptográfico (Challenge) del Servidor IAM → 2. startAuthentication
// (el autenticador genera la Firma Digital FIDO2 con la llave privada) →
// 3. Verificación en Servidor IAM y emisión del Token JWT de Acceso Unificado.
$('btn-login').addEventListener('click', async () => {
  const email = $('login-email').value.trim();
  if (!email) return audit('Acceso Corporativo: ingresa tu email.', 'err');
  try {
    audit(`Acceso Corporativo: solicitando Reto Criptográfico (Challenge) para ${email}…`);
    const optionsJSON = await postJSON('/api/auth/login-challenge', { email });
    audit('Acceso Corporativo: Reto Criptográfico (Challenge) recibido. Esperando Firma Digital FIDO2…');
    const asseResp = await startAuthentication({ optionsJSON });
    audit('Acceso Corporativo: Firma Digital FIDO2 generada. Verificación en Servidor IAM…');
    const result = await postJSON('/api/auth/login-verify', { email, asseResp });
    state.user = result.user;
    state.token = result.token;
    state.tokenVisible = false;
    renderDashboard();
    audit(`Acceso Corporativo OK: Token JWT de Acceso Unificado emitido para ${result.user.email}.`, 'ok');
    await loadPymeData();
    goTab('dashboard');
  } catch (err) {
    audit(`Acceso Corporativo fallido: ${err.message}`, 'err');
  }
});

// --------------------------------------------------------------- arranque
(async function init() {
  setAuthMode('register');
  renderDashboard();
  audit('Frontend IAM cargado. Protocolo WebAuthn/FIDO2 listo.');
  try {
    const r = await fetch('/api/health');
    const h = await r.json();
    $('audit-backend').textContent = h.ok ? `en línea (RP_ID: ${h.rpId})` : 'respuesta inesperada';
    audit(`Servidor IAM: ${JSON.stringify(h)}`, 'ok');
  } catch {
    $('audit-backend').textContent = 'no disponible';
    audit('Servidor IAM no disponible. ¿Servidor en marcha?', 'err');
  }
})();
