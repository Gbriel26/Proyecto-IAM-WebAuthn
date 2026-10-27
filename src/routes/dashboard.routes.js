const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Catálogo simulado de módulos PyME por Rol del Empleado (Tabla 1).
// El rol vigente lo obtiene requireAuth desde PostgreSQL (no del JWT congelado).
const MODULOS_POR_ROL = {
  admin: {
    nivel_acceso: 'total',
    modulos: [
      { id: 'usuarios', nombre: 'Gestión de Empleados IAM', descripcion: 'Altas, roles y estados' },
      { id: 'auditoria', nombre: 'Auditoría del Sistema', descripcion: 'Logs WebAuthn/FIDO2 y sesiones' },
      { id: 'inventario', nombre: 'Inventario PyME', descripcion: 'Stock y movimientos' },
      { id: 'facturacion', nombre: 'Facturación', descripcion: 'Ventas y comprobantes' },
      { id: 'reportes', nombre: 'Reportes Gerenciales', descripcion: 'KPIs y cierres' },
      { id: 'config', nombre: 'Configuración', descripcion: 'Parámetros del Relying Party' },
    ],
  },
  gerencia: {
    nivel_acceso: 'alto',
    modulos: [
      { id: 'reportes', nombre: 'Reportes Gerenciales', descripcion: 'KPIs y cierres' },
      { id: 'facturacion', nombre: 'Facturación', descripcion: 'Ventas y comprobantes' },
      { id: 'inventario', nombre: 'Inventario PyME', descripcion: 'Stock y movimientos (lectura)' },
      { id: 'dashboard', nombre: 'Tablero PyME', descripcion: 'Resumen operativo' },
    ],
  },
  operativo: {
    nivel_acceso: 'medio',
    modulos: [
      { id: 'inventario', nombre: 'Inventario PyME', descripcion: 'Stock y movimientos' },
      { id: 'tareas', nombre: 'Tareas Operativas', descripcion: 'Órdenes del día' },
      { id: 'asistencia', nombre: 'Asistencia', descripcion: 'Registro de jornada' },
    ],
  },
  usuario: {
    nivel_acceso: 'básico',
    modulos: [
      { id: 'perfil', nombre: 'Mi Perfil', descripcion: 'Datos del empleado' },
      { id: 'accesos', nombre: 'Mis Accesos', descripcion: 'Historial de sesiones IAM' },
    ],
  },
};

/**
 * GET /api/dashboard/pyme-data
 * Ruta protegida: requiere Token JWT de Acceso Unificado válido.
 * Devuelve los módulos habilitados según el rol del empleado.
 */
router.get('/pyme-data', requireAuth, (req, res) => {
  const rol = (req.user.rol || 'usuario').toLowerCase();
  const data = MODULOS_POR_ROL[rol] || MODULOS_POR_ROL.usuario;
  return res.json({
    empresa: 'PyME — Plataforma protegida por IAM WebAuthn',
    usuario: req.user,
    rol,
    nivel_acceso: data.nivel_acceso,
    modulos: data.modulos,
  });
});

module.exports = router;
