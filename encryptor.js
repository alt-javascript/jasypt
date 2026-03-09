import crypto from 'crypto';
import assert from 'assert';
import des from 'des.js';
import { isEmpty } from "./util.js";

const DESCBC = des.CBC.instantiate(des.DES);
const EDECBC = des.CBC.instantiate(des.EDE);

// PBE1:  iterative-hash KDF (EVP_BytesToKey-style) + des.js cipher, 8-byte salt
// PBE1N: iterative-hash KDF + Node.js crypto cipher, 8-byte salt
// PBE2:  PBKDF2 + AES-CBC via Node.js crypto, 16-byte salt + 16-byte IV
const ALGO_CONFIG = {
  'PBEWITHMD5ANDDES':              { type: 'pbe1',  hash: 'md5',        Cipher: DESCBC,  keyLen: 8,  ivLen: 8 },
  'PBEWITHMD5ANDTRIPLEDES':        { type: 'pbe1',  hash: 'md5',        Cipher: EDECBC,  keyLen: 24, ivLen: 8 },
  'PBEWITHSHA1ANDDESEDE':          { type: 'pbe1',  hash: 'sha1',       Cipher: EDECBC,  keyLen: 24, ivLen: 8 },
  'PBEWITHSHA1ANDRC2_128':         { type: 'pbe1n', hash: 'sha1', nodeCipher: 'rc2-cbc',    keyLen: 16, ivLen: 8 },
  'PBEWITHSHA1ANDRC2_40':          { type: 'pbe1n', hash: 'sha1', nodeCipher: 'rc2-40-cbc', keyLen: 5,  ivLen: 8 },
  'PBEWITHSHA1ANDRC4_128':         { type: 'pbe1n', hash: 'sha1', nodeCipher: 'rc4',         keyLen: 16, ivLen: 0 },
  'PBEWITHSHA1ANDRC4_40':          { type: 'pbe1n', hash: 'sha1', nodeCipher: 'rc4-40',      keyLen: 5,  ivLen: 0 },
  'PBEWITHHMACSHA1ANDAES_128':         { type: 'pbe2', hmac: 'sha1',       keyLen: 16 },
  'PBEWITHHMACSHA1ANDAES_256':         { type: 'pbe2', hmac: 'sha1',       keyLen: 32 },
  'PBEWITHHMACSHA224ANDAES_128':       { type: 'pbe2', hmac: 'sha224',     keyLen: 16 },
  'PBEWITHHMACSHA224ANDAES_256':       { type: 'pbe2', hmac: 'sha224',     keyLen: 32 },
  'PBEWITHHMACSHA256ANDAES_128':       { type: 'pbe2', hmac: 'sha256',     keyLen: 16 },
  'PBEWITHHMACSHA256ANDAES_256':       { type: 'pbe2', hmac: 'sha256',     keyLen: 32 },
  'PBEWITHHMACSHA384ANDAES_128':       { type: 'pbe2', hmac: 'sha384',     keyLen: 16 },
  'PBEWITHHMACSHA384ANDAES_256':       { type: 'pbe2', hmac: 'sha384',     keyLen: 32 },
  'PBEWITHHMACSHA512/224ANDAES_128':   { type: 'pbe2', hmac: 'sha512-224', keyLen: 16 },
  'PBEWITHHMACSHA512/224ANDAES_256':   { type: 'pbe2', hmac: 'sha512-224', keyLen: 32 },
  'PBEWITHHMACSHA512/256ANDAES_128':   { type: 'pbe2', hmac: 'sha512-256', keyLen: 16 },
  'PBEWITHHMACSHA512/256ANDAES_256':   { type: 'pbe2', hmac: 'sha512-256', keyLen: 32 },
  'PBEWITHHMACSHA512ANDAES_128':       { type: 'pbe2', hmac: 'sha512',     keyLen: 16 },
  'PBEWITHHMACSHA512ANDAES_256':       { type: 'pbe2', hmac: 'sha512',     keyLen: 32 },
};

const PBE1_SALT_LEN = 8;
const PBE2_SALT_LEN = 16;
const PBE2_IV_LEN   = 16;

export const SUPPORTED_ALGORITHMS = Object.keys(ALGO_CONFIG);

export default class Encryptor {
  constructor(opts = {}) {
    this.setAlgorithm(opts.algorithm || 'PBEWITHMD5ANDDES');
    const saltLen = ALGO_CONFIG[this.algorithm].type === 'pbe2' ? PBE2_SALT_LEN : PBE1_SALT_LEN;
    this.salt = opts.salt || crypto.randomBytes(saltLen);
    this.iterations = opts.iterations || 1000;
  }

  /**
   * Set the encryption algorithm
   * @param {String} algorithm algorithm name
   */
  setAlgorithm(algorithm) {
    const normalized = algorithm.toUpperCase();
    assert(ALGO_CONFIG[normalized], `Unsupported algorithm: ${algorithm}`);
    this.algorithm = normalized;
  }

  /**
   * Set the encryption salt
   * @param {Buffer} salt salt bytes, or null/undefined to generate randomly
   */
  setSalt(salt) {
    const saltLen = ALGO_CONFIG[this.algorithm].type === 'pbe2' ? PBE2_SALT_LEN : PBE1_SALT_LEN;
    this.salt = isEmpty(salt) ? crypto.randomBytes(saltLen) : Buffer.from(salt);
  }

  /**
   * Set the iteration count
   * @param {Number} iterations iteration count
   */
  setIterations(iterations) {
    this.iterations = iterations || 1000;
  }

  /**
   * Derive key material using OpenSSL EVP_BytesToKey-compatible KDF.
   * Produces successive hash blocks: H_i = Hash^n(H_{i-1} || password || salt)
   * @param {String} hashAlg hash algorithm name
   * @param {String} password secret key
   * @param {Buffer} salt random salt
   * @param {Number} iterations iteration count
   * @param {Number} totalBytes total bytes of key material needed
   */
  KDF(hashAlg, password, salt, iterations, totalBytes) {
    const pwd = Buffer.from(password, 'utf-8');
    let result = Buffer.alloc(0);
    let prev = Buffer.alloc(0);

    while (result.length < totalBytes) {
      let block = Buffer.concat([prev, pwd, salt]);
      for (let i = 0; i < iterations; i++) {
        block = crypto.createHash(hashAlg).update(block).digest();
      }
      result = Buffer.concat([result, block]);
      prev = block;
    }

    return result.subarray(0, totalBytes);
  }

  /**
   * Derive the cipher key and IV from password, salt, and iterations (PBE1/PBE1N only)
   * @param {String} password secret key
   * @param {Buffer} salt random salt
   * @param {Number} iterations iteration count
   */
  getKeyIV(password, salt, iterations) {
    const { hash, keyLen, ivLen } = ALGO_CONFIG[this.algorithm];
    const derived = this.KDF(hash, password, salt, iterations, keyLen + ivLen);
    return [derived.subarray(0, keyLen), derived.subarray(keyLen)];
  }

  /**
   * Encrypt a plaintext payload
   * @param {String} payload text to encrypt
   * @param {String} password secret key
   * @param {Buffer} salt random salt (optional, defaults to instance salt)
   * @param {Number} iterations iteration count (optional, defaults to instance iterations)
   */
  encrypt(payload, password, salt, iterations) {
    const cfg = ALGO_CONFIG[this.algorithm];
    const _salt = salt ?? this.salt;
    const _iterations = iterations ?? this.iterations;

    if (cfg.type === 'pbe1') {
      const kiv = this.getKeyIV(password || '', _salt, _iterations);
      const cipher = cfg.Cipher.create({ type: 'encrypt', key: Array.from(kiv[0]), iv: Array.from(kiv[1]) });
      const out = Buffer.from(cipher.update(Array.from(Buffer.from(payload, 'utf-8'))).concat(cipher.final()));
      return Buffer.concat([_salt, out]).toString('base64');
    }

    if (cfg.type === 'pbe1n') {
      const kiv = this.getKeyIV(password || '', _salt, _iterations);
      const iv = cfg.ivLen > 0 ? kiv[1] : null;
      const cipher = crypto.createCipheriv(cfg.nodeCipher, kiv[0], iv);
      const out = Buffer.concat([cipher.update(Buffer.from(payload, 'utf-8')), cipher.final()]);
      return Buffer.concat([_salt, out]).toString('base64');
    }

    // pbe2: PBKDF2 + AES-CBC
    const iv = crypto.randomBytes(PBE2_IV_LEN);
    const key = crypto.pbkdf2Sync(password || '', _salt, _iterations, cfg.keyLen, cfg.hmac);
    const cipher = crypto.createCipheriv(`aes-${cfg.keyLen * 8}-cbc`, key, iv);
    const out = Buffer.concat([cipher.update(Buffer.from(payload, 'utf-8')), cipher.final()]);
    return Buffer.concat([_salt, iv, out]).toString('base64');
  }

  /**
   * Decrypt a base64-encoded encrypted payload
   * @param {String} payload base64 ciphertext to decrypt
   * @param {String} password secret key
   * @param {Number} iterations iteration count (optional, defaults to instance iterations)
   */
  decrypt(payload, password, iterations) {
    const cfg = ALGO_CONFIG[this.algorithm];
    const _iterations = iterations ?? this.iterations;
    const buf = Buffer.from(payload, 'base64');

    if (cfg.type === 'pbe1') {
      const salt = buf.subarray(0, PBE1_SALT_LEN);
      const ciphertext = buf.subarray(PBE1_SALT_LEN);
      const kiv = this.getKeyIV(password || '', salt, _iterations);
      const decipher = cfg.Cipher.create({ type: 'decrypt', key: Array.from(kiv[0]), iv: Array.from(kiv[1]) });
      return Buffer.from(decipher.update(Array.from(ciphertext)).concat(decipher.final())).toString('utf-8');
    }

    if (cfg.type === 'pbe1n') {
      const salt = buf.subarray(0, PBE1_SALT_LEN);
      const ciphertext = buf.subarray(PBE1_SALT_LEN);
      const kiv = this.getKeyIV(password || '', salt, _iterations);
      const iv = cfg.ivLen > 0 ? kiv[1] : null;
      const decipher = crypto.createDecipheriv(cfg.nodeCipher, kiv[0], iv);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
    }

    // pbe2: PBKDF2 + AES-CBC
    const salt = buf.subarray(0, PBE2_SALT_LEN);
    const iv = buf.subarray(PBE2_SALT_LEN, PBE2_SALT_LEN + PBE2_IV_LEN);
    const ciphertext = buf.subarray(PBE2_SALT_LEN + PBE2_IV_LEN);
    const key = crypto.pbkdf2Sync(password || '', salt, _iterations, cfg.keyLen, cfg.hmac);
    const decipher = crypto.createDecipheriv(`aes-${cfg.keyLen * 8}-cbc`, key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
  }
}

Encryptor.SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS;