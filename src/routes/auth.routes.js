const express = require('express');
const authController = require('../controllers/auth.controller');

const router = express.Router();

// --- Registro (attestation / creación de credencial) ---
// 1. El frontend pide un reto criptográfico (challenge) para registrarse.
router.post('/register-challenge', authController.registerChallenge);
// 2. El frontend responde con la attestation firmada por el autenticador.
router.post('/register-verify', authController.registerVerify);

// --- Login (assertion / uso de credencial existente) ---
// 1. El frontend pide un reto para autenticarse.
router.post('/login-challenge', authController.loginChallenge);
// 2. El frontend responde con la assertion firmada. Si verifica, se emite JWT.
router.post('/login-verify', authController.loginVerify);

// --- Cierre de sesión real: invalida la sesión en PostgreSQL ---
router.post('/logout', authController.logout);

module.exports = router;
