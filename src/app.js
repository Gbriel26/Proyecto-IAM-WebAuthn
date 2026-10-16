const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');

const authRoutes = require('./routes/auth.routes');
const dashboardRoutes = require('./routes/dashboard.routes');

const app = express();

// CORS: en demo local permite el ORIGIN del frontend.
// En producción restringe a tus dominios reales.
app.use(
  cors({
    origin: process.env.ORIGIN || 'http://localhost:3000',
    credentials: true,
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Frontend estático de demostración
app.use(express.static(path.join(__dirname, '..', 'public')));

// Rutas del IAM
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Healthcheck útil para la defensa del proyecto
app.get('/api/health', (_req, res) => res.json({ ok: true, rpId: process.env.RP_ID }));

// 404 JSON para rutas API desconocidas
app.use('/api', (_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

module.exports = app;
