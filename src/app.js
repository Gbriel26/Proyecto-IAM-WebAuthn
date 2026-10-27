'use strict';

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const config = require('./config/env');
const db = require('./config/db');
const authRoutes = require('./routes/auth.routes');
const dashboardRoutes = require('./routes/dashboard.routes');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', config.trustProxy);

// ---------------------------------------------------------------------------
// Trazabilidad y cabeceras de seguridad
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Permissions-Policy',
    'publickey-credentials-get=(self), publickey-credentials-create=(self), ' +
      'geolocation=(), microphone=(), camera=()'
  );
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self' https://esm.sh; " +
      "style-src 'self'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "base-uri 'none'; " +
      "form-action 'self'; " +
      "frame-ancestors 'none'"
  );
  if (config.isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// ---------------------------------------------------------------------------
// CORS: solo los orígenes declarados en ORIGIN (lista separada por comas).
// ---------------------------------------------------------------------------
app.use(
  cors({
    origin(origin, callback) {
      // Sin cabecera Origin: peticiones same-origin, curl o pruebas.
      if (!origin) return callback(null, true);
      if (config.origins.includes(origin)) return callback(null, true);

      const error = new Error('Origen no permitido por CORS');
      error.status = 403;
      return callback(error);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  })
);

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Rutas del IAM
// ---------------------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);

app.get('/api/health', async (_req, res) => {
  try {
    await db.query('SELECT 1');
    return res.json({
      ok: true,
      db: 'up',
      rpId: config.rpId,
      uptime: Math.floor(process.uptime()),
    });
  } catch {
    return res.status(503).json({ ok: false, db: 'down', rpId: config.rpId });
  }
});

// 404 JSON para rutas API desconocidas.
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada', request_id: req.id });
});

// Frontend estático de demostración.
app.use(express.static(path.join(__dirname, '..', 'public')));

// ---------------------------------------------------------------------------
// Manejo centralizado de errores (JSON inválido, CORS, fallos internos).
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  let status = Number(err.status) || 500;
  let message = 'Error interno del servidor';

  if (err.type === 'entity.parse.failed') {
    status = 400;
    message = 'JSON inválido en el cuerpo de la petición';
  } else if (err.type === 'entity.too.large') {
    status = 413;
    message = 'Cuerpo de la petición demasiado grande';
  } else if (status < 500) {
    message = err.message;
  } else {
    console.error(`[iam][error][${req.id || '-'}]`, err);
  }

  return res.status(status).json({ error: message, request_id: req.id });
});

module.exports = app;
