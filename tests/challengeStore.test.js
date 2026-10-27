'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { ChallengeStore } = require('../src/utils/challengeStore');

test('expira los retos después del TTL', () => {
  let now = 1_000;
  const store = new ChallengeStore({ ttlMs: 100, now: () => now });

  store.set('a', { challenge: 'x' });
  assert.deepEqual(store.get('a'), { challenge: 'x' });

  now += 99;
  assert.deepEqual(store.get('a'), { challenge: 'x' });

  now += 2;
  assert.equal(store.get('a'), null);
  assert.equal(store.size, 0);

  store.close();
});

test('consume es de un solo uso', () => {
  const store = new ChallengeStore({ ttlMs: 1_000 });

  store.set('b', { challenge: 'y' });
  assert.deepEqual(store.consume('b'), { challenge: 'y' });
  assert.equal(store.consume('b'), null);
  assert.equal(store.get('b'), null);

  store.close();
});

test('respeta la cota de entradas descartando la más antigua', () => {
  const store = new ChallengeStore({ ttlMs: 10_000, maxEntries: 2 });

  store.set('1', { n: 1 });
  store.set('2', { n: 2 });
  store.set('3', { n: 3 });

  assert.equal(store.size, 2);
  assert.equal(store.get('1'), null);
  assert.deepEqual(store.get('2'), { n: 2 });
  assert.deepEqual(store.get('3'), { n: 3 });

  store.close();
});

test('rechaza TTL inválido', () => {
  assert.throws(() => new ChallengeStore({ ttlMs: 0 }), /ttlMs/);
  assert.throws(() => new ChallengeStore({ ttlMs: Number.NaN }), /ttlMs/);
});
