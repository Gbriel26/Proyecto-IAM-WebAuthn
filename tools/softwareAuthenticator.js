'use strict';

/**
 * Autenticador WebAuthn de software para PRUEBAS y BENCHMARK.
 *
 * No forma parte del middleware: simula un autenticador FIDO2 (Windows Hello
 * o YubiKey) generando un par de claves P-256 y firmando los retos con
 * ECDSA/ES256. Permite ejecutar el flujo completo (attestation + assertion)
 * sin navegador ni hardware, de forma reproducible en CI.
 *
 * Limitación: no implementa attestation con certificado (fmt "none") ni
 * transporte real; el objetivo es validar la lógica del servidor.
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Codificador CBOR mínimo (RFC 8949) para el attestationObject y la COSE key.
// Solo soporta enteros, strings, bytes, arrays y mapas, que es lo que exige
// WebAuthn para attestation "none".
// ---------------------------------------------------------------------------
function cborHead(majorType, length) {
  if (length < 24) return Buffer.from([(majorType << 5) | length]);
  if (length < 0x100) return Buffer.from([(majorType << 5) | 24, length]);
  if (length < 0x10000) {
    const buffer = Buffer.alloc(3);
    buffer[0] = (majorType << 5) | 25;
    buffer.writeUInt16BE(length, 1);
    return buffer;
  }
  const buffer = Buffer.alloc(5);
  buffer[0] = (majorType << 5) | 26;
  buffer.writeUInt32BE(length, 1);
  return buffer;
}

function cborEncode(value) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('CBOR: solo se admiten enteros');
    return value >= 0
      ? cborHead(0, value)
      : cborHead(1, -1 - value);
  }

  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHead(2, bytes.length), bytes]);
  }

  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(cborEncode)]);
  }

  if (value instanceof Map) {
    const parts = [cborHead(5, value.size)];
    for (const [key, entryValue] of value) {
      parts.push(cborEncode(key), cborEncode(entryValue));
    }
    return Buffer.concat(parts);
  }

  throw new Error(`CBOR: tipo no soportado (${typeof value})`);
}

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

class SoftwareAuthenticator {
  /**
   * @param {object} options
   * @param {string} options.origin  Origin exacto del RP (p. ej. http://localhost:3000)
   * @param {'platform'|'cross-platform'} [options.attachment]
   * @param {Buffer} [options.aaguid] 16 bytes; por defecto todo ceros
   */
  constructor({ origin, attachment = 'platform', aaguid } = {}) {
    if (!origin) throw new Error('SoftwareAuthenticator requiere origin');

    this.origin = origin;
    this.attachment = attachment;
    this.aaguid = aaguid || Buffer.alloc(16);
    this.counter = 0;
    this.credentialId = crypto.randomBytes(32);
    this.rpId = null;

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    this.privateKey = privateKey;
    this.publicKey = publicKey;

    const jwk = publicKey.export({ format: 'jwk' });
    this.cosePublicKey = cborEncode(
      new Map([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(jwk.x, 'base64url')],
        [-3, Buffer.from(jwk.y, 'base64url')],
      ])
    );
  }

  _authenticatorData({ includeAttestedCredentialData, flags }) {
    const rpIdHash = sha256(Buffer.from(this.rpId, 'utf8'));
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter >>> 0, 0);

    const parts = [rpIdHash, Buffer.from([flags]), counter];

    if (includeAttestedCredentialData) {
      const credIdLength = Buffer.alloc(2);
      credIdLength.writeUInt16BE(this.credentialId.length, 0);
      parts.push(this.aaguid, credIdLength, this.credentialId, this.cosePublicKey);
    }

    return Buffer.concat(parts);
  }

  /**
   * Responde a PublicKeyCredentialCreationOptionsJSON.
   * @returns {object} RegistrationResponseJSON
   */
  async register(optionsJSON) {
    this.rpId = optionsJSON.rp.id;
    this.challenge = optionsJSON.challenge;

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: optionsJSON.challenge,
        origin: this.origin,
        crossOrigin: false,
      }),
      'utf8'
    );

    // UP (0x01) + UV (0x04) + AT (0x40)
    const authData = this._authenticatorData({
      includeAttestedCredentialData: true,
      flags: 0x45,
    });

    const attestationObject = cborEncode(
      new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ])
    );

    return {
      id: base64url(this.credentialId),
      rawId: base64url(this.credentialId),
      type: 'public-key',
      authenticatorAttachment: this.attachment,
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
        transports: this.attachment === 'platform' ? ['internal'] : ['usb', 'nfc'],
      },
    };
  }

  /**
   * Responde a PublicKeyCredentialRequestOptionsJSON.
   * @returns {object} AuthenticationResponseJSON
   */
  async authenticate(optionsJSON) {
    if (!this.rpId) throw new Error('Llama primero a register()');
    this.counter += 1;

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: optionsJSON.challenge,
        origin: this.origin,
        crossOrigin: false,
      }),
      'utf8'
    );

    // UP (0x01) + UV (0x04)
    const authData = this._authenticatorData({
      includeAttestedCredentialData: false,
      flags: 0x05,
    });

    const signature = crypto.sign(
      'sha256',
      Buffer.concat([authData, sha256(clientDataJSON)]),
      this.privateKey
    );

    return {
      id: base64url(this.credentialId),
      rawId: base64url(this.credentialId),
      type: 'public-key',
      authenticatorAttachment: this.attachment,
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64url(clientDataJSON),
        authenticatorData: base64url(authData),
        signature: base64url(signature),
      },
    };
  }
}

module.exports = { SoftwareAuthenticator, cborEncode };
