'use strict';

/**
 * Almacén de retos criptográficos (challenges) con expiración y límite de
 * tamaño. Sustituye los `Map` eternos que permitían replays y fugas de
 * memoria.
 *
 * En producción con varias instancias esto debe reemplazarse por Redis con
 * TTL. Para una sola instancia (el alcance de la tesis) es suficiente y no
 * añade dependencias.
 */
class ChallengeStore {
  constructor({ ttlMs, maxEntries = 10_000, now = Date.now } = {}) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('ChallengeStore: ttlMs debe ser un número positivo');
    }
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = now;
    this.entries = new Map();

    // Barrido periódico para liberar memoria aunque no lleguen peticiones.
    // `unref()` evita que el temporizador mantenga vivo el proceso.
    this.sweeper = setInterval(() => this.sweep(), Math.min(ttlMs, 60_000));
    if (typeof this.sweeper.unref === 'function') this.sweeper.unref();
  }

  _purgeExpired() {
    const current = this.now();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= current) this.entries.delete(key);
    }
  }

  set(key, value) {
    this._purgeExpired();

    // Cota dura de memoria: si se llena, se descarta el reto más antiguo.
    if (!this.entries.has(key) && this.entries.size >= this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey !== undefined) this.entries.delete(oldestKey);
    }

    this.entries.set(key, { value, expiresAt: this.now() + this.ttlMs });
    return value;
  }

  get(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    return entry.value;
  }

  /**
   * Recupera y elimina el reto. Garantiza un único uso: un challenge no
   * puede reutilizarse ni siquiera si la verificación falla.
   */
  consume(key) {
    const value = this.get(key);
    if (value !== null) this.entries.delete(key);
    return value;
  }

  delete(key) {
    this.entries.delete(key);
  }

  sweep() {
    this._purgeExpired();
  }

  get size() {
    return this.entries.size;
  }

  close() {
    clearInterval(this.sweeper);
    this.entries.clear();
  }
}

module.exports = { ChallengeStore };
