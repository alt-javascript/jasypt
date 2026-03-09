import assert from 'assert';
import crypto from 'crypto';

// Maps jasypt-compatible algorithm names to Node.js crypto hash names
const ALGO_MAP = {
  'MD2':         'md2',
  'MD5':         'md5',
  'SHA-1':       'sha1',
  'SHA-224':     'sha224',
  'SHA-256':     'sha256',
  'SHA-384':     'sha384',
  'SHA-512':     'sha512',
  'SHA-512/224': 'sha512-224',
  'SHA-512/256': 'sha512-256',
  'SHA3-224':    'sha3-224',
  'SHA3-256':    'sha3-256',
  'SHA3-384':    'sha3-384',
  'SHA3-512':    'sha3-512',
};

const _availableHashes = new Set(crypto.getHashes());

class Digester {
  constructor() {
    this.algorithm = 'SHA-256';
    this.saltSize = 8;
    this.iterations = 1000;
  }

  /**
   * Set the digest algorithm
   * @param {String} algorithm algorithm name (e.g. 'SHA-256')
   */
  setAlgorithm(algorithm) {
    assert(ALGO_MAP[algorithm], `Unsupported digest algorithm: ${algorithm}`);
    assert(_availableHashes.has(ALGO_MAP[algorithm]), `Digest algorithm ${algorithm} is not available in this OpenSSL build`);
    this.algorithm = algorithm;
  }

  /**
   * Set the salt size in bytes
   * @param {Number} size number of salt bytes
   */
  setSaltSize(size) {
    this.saltSize = size;
  }

  /**
   * Set the number of hash iterations
   * @param {Number} iterations iteration count
   */
  setIterations(iterations) {
    this.iterations = iterations;
  }

  /**
   * Compute the iterated hash.
   * First iteration: Hash(salt || message). Subsequent: Hash(digest).
   * @param {String} hashAlg create-hash algorithm name
   * @param {Buffer} salt random salt
   * @param {String} message plaintext message
   * @param {Number} iterations iteration count
   * @return {Buffer} raw digest bytes
   */
  _compute(hashAlg, salt, message, iterations) {
    const msg = Buffer.from(message, 'utf-8');
    let digest = crypto.createHash(hashAlg).update(salt).update(msg).digest();
    for (let i = 1; i < iterations; i++) {
      digest = crypto.createHash(hashAlg).update(digest).digest();
    }
    return digest;
  }

  /**
   * Digest a plaintext message
   * @param {String} message message to digest
   * @return {String} base64-encoded salt + digest
   */
  digest(message) {
    const salt = crypto.randomBytes(this.saltSize);
    const hashAlg = ALGO_MAP[this.algorithm];
    const digest = this._compute(hashAlg, salt, message, this.iterations);
    return Buffer.concat([salt, digest]).toString('base64');
  }

  /**
   * Check whether a plaintext message matches a stored digest
   * @param {String} message plaintext message to verify
   * @param {String} storedDigest base64-encoded stored digest
   * @return {Boolean} true if the message matches
   */
  matches(message, storedDigest) {
    const stored = Buffer.from(storedDigest, 'base64');
    const salt = stored.subarray(0, this.saltSize);
    const expected = stored.subarray(this.saltSize);
    const hashAlg = ALGO_MAP[this.algorithm];
    const computed = this._compute(hashAlg, salt, message, this.iterations);
    if (computed.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed[i] ^ expected[i];
    }
    return diff === 0;
  }
}

Digester.SUPPORTED_ALGORITHMS = Object.keys(ALGO_MAP).filter(k => _availableHashes.has(ALGO_MAP[k]));

export default Digester;
