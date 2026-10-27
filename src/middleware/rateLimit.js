'use strict';

/**
 * Rate limiter en memoria (ventana fija) sin dependencias externas.
 *
 * Protege los endpoints de autenticación contra fuerza bruta, enumeración de
 * usuarios y abuso de la generación de challenges. La clave es IP + ruta, de
 * modo que un ataque contra /login-challenge no agota el cupo de /register.
 *
 * En un despliegue con varias instancias se sustituye por Redis; el alcance
 * de la tesis es una sola instancia.
 */
function createRateLimiter({
  windowMs = 60_000,
  max = 120,
  message = 'Demasiadas solicitudes. Intenta de nuevo más tarde.',
  keyGenerator,
  now = Date.now,
} = {}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new Error('createRateLimiter: windowMs inválido');
  }
  if (!Number.isFinite(max) || max <= 0) {
    throw new Error('createRateLimiter: max inválido');
  }

  const hits = new Map(); // clave -> { count, resetAt }

  const sweeper = setInterval(() => {
    const current = now();
    for (const [key, entry] of hits) {
      if (entry.resetAt <= current) hits.delete(key);
    }
  }, Math.min(windowMs, 60_000));
  if (typeof sweeper.unref === 'function') sweeper.unref();

  return function rateLimiter(req, res, next) {
    const key = keyGenerator
      ? keyGenerator(req)
      : `${req.ip || req.socket?.remoteAddress || 'desconocido'}|${req.method}|${req.baseUrl}${req.path}`;

    const current = now();
    let entry = hits.get(key);

    if (!entry || entry.resetAt <= current) {
      entry = { count: 0, resetAt: current + windowMs };
      hits.set(key, entry);
    }

    entry.count += 1;
    const remaining = Math.max(0, max - entry.count);

    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > max) {
      const retryAfter = Math.max(1, Math.ceil((entry.resetAt - current) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: message });
    }

    return next();
  };
}

module.exports = { createRateLimiter };
