'use strict';

const express = require('express');
const authController = require('../controllers/auth.controller');
const config = require('../config/env');
const { createRateLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Límite general para todo /api/auth (fuerza bruta / scraping).
const authLimiter = createRateLimiter({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  message: 'Demasiadas solicitudes de autenticación. Espera un momento.',
});

// Límite estricto para ceremonias WebAuthn (generación y verificación).
const ceremonyLimiter = createRateLimiter({
  windowMs: config.rateLimit.strictWindowMs,
  max: config.rateLimit.strictMax,
  message: 'Demasiados intentos de autenticación. Espera antes de reintentar.',
});

router.use(authLimiter);

// --- Registro (attestation / creación de credencial) ---
router.post('/register-challenge', ceremonyLimiter, authController.registerChallenge);
router.post('/register-verify', ceremonyLimiter, authController.registerVerify);

// --- Login (assertion / uso de credencial existente) ---
router.post('/login-challenge', ceremonyLimiter, authController.loginChallenge);
router.post('/login-verify', ceremonyLimiter, authController.loginVerify);

// --- Cierre de sesión real: invalida la sesión en PostgreSQL ---
router.post('/logout', authController.logout);

module.exports = router;
