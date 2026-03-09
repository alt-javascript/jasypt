import assert from 'assert';
import crypto from 'crypto';
import {isEmpty} from "./util.js";

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
  constructor(opts = {}) {
    this.setAlgorithm(opts.algorithm || 'SHA-256');
    this.salt = opts.salt || null;
    this.saltSize = 8;
    this.iterations = opts.iterations || 1000;
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
   * Set a fixed salt string used for digest and matches
   * @param {String} salt fixed salt value
   */
  setSalt(salt) {
    this.salt = salt;
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
   * @param {String} hashAlg Node.js crypto algorithm name
   * @param {Buffer} salt salt bytes
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
   * Digest a plaintext message.
   * Output format: base64(salt_bytes + hash_bytes)
   * @param {String} message message to digest
   * @param {String} salt optional fixed salt (overrides this.salt)
   * @param {Number} iterations optional iteration count
   * @return {String} base64-encoded salt + digest
   */
  digest(message, salt, iterations) {
    const _salt = !isEmpty(salt)      ? Buffer.from(salt)
                : !isEmpty(this.salt)  ? Buffer.from(this.salt)
                : crypto.randomBytes(this.saltSize);
    const hashAlg = ALGO_MAP[this.algorithm];
    const digest = this._compute(hashAlg, _salt, message, iterations || this.iterations);
    return Buffer.concat([_salt, digest]).toString('base64');
  }

  /**
   * Check whether a plaintext message matches a stored digest.
   * For random-salt digests, the salt is extracted from the first saltSize bytes of the stored value.
   * For fixed-salt digests (this.salt set), that salt is used directly.
   * @param {String} message plaintext message to verify
   * @param {String} storedDigest base64-encoded stored digest
   * @param {String} salt optional fixed salt (overrides this.salt)
   * @param {Number} iterations optional iteration count
   * @return {Boolean} true if the message matches
   */
  matches(message, storedDigest, salt, iterations) {
    const stored = Buffer.from(storedDigest, 'base64');
    const _salt = !isEmpty(salt)      ? Buffer.from(salt)
                : !isEmpty(this.salt)  ? Buffer.from(this.salt)
                : stored.subarray(0, this.saltSize);
    const expected = stored.subarray(_salt.length);
    const hashAlg = ALGO_MAP[this.algorithm];
    const computed = this._compute(hashAlg, _salt, message, iterations || this.iterations);
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
