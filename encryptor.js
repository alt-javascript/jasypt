import crypto from 'crypto';
import assert from 'assert';
import createHash from 'create-hash';
import des from 'des.js';
import {isEmpty} from "./util.js";

const DESCBC = des.CBC.instantiate(des.DES);
const EDECBC = des.CBC.instantiate(des.EDE);

const ALGO_CONFIG = {
  'PBEWITHMD5ANDDES':       { hash: 'md5',  Cipher: DESCBC, keyLen: 8,  ivLen: 8 },
  'PBEWITHMD5ANDTRIPLEDES': { hash: 'md5',  Cipher: EDECBC, keyLen: 24, ivLen: 8 },
  'PBEWITHSHA1ANDDESEDE':   { hash: 'sha1', Cipher: EDECBC, keyLen: 24, ivLen: 8 },
};

export default class Encryptor {
  constructor(opts = {}) {
    this.setAlgorithm( opts.algorithm ||'PBEWITHMD5ANDDES');
    this.salt = opts.salt || crypto.randomBytes(8);
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
   * @param {String} salt algorithm salt
   */
  setSalt(salt) {
    // this.salt = isEmpty(salt) ? crypto.randomBytes(8) : Buffer.from(salt);
    this.salt =  crypto.randomBytes(8);
  }

  /**
   * Set the encryption salt
   * @param {Integer} iterations algorithm iterations
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
        block = createHash(hashAlg).update(block).digest();
      }
      result = Buffer.concat([result, block]);
      prev = block;
    }

    return result.subarray(0, totalBytes);
  }

  /**
   * Derive the cipher key and IV from password, salt, and iterations
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
   * @param {Buffer} salt random salt
   * @param {Number} iterations iteration count
   */
  encrypt(payload, password, salt, iterations) {
    const _salt = salt ?? this.salt
    const { Cipher } = ALGO_CONFIG[this.algorithm];
    const kiv = this.getKeyIV(password || '', _salt, iterations ?? this.iterations);
    const cipher = Cipher.create({ type: 'encrypt', key: Array.from(kiv[0]), iv: Array.from(kiv[1]) });

    const input = Array.from(Buffer.from(payload, 'utf-8'));
    const out = Buffer.from(cipher.update(input).concat(cipher.final()));
    const result = Buffer.alloc(out.length + _salt.length);

    _salt.copy(result, 0, 0, _salt.length);
    out.copy(result, _salt.length, 0, out.length);

    return result.toString('base64');
  }

  /**
   * Decrypt a base64-encoded encrypted payload
   * @param {String} payload base64 ciphertext to decrypt
   * @param {String} password secret key
   * @param {Number} iterations iteration count
   */
  decrypt(payload, password, iterations) {
    const { Cipher } = ALGO_CONFIG[this.algorithm];
    const encryptedMessage = Buffer.from(payload, 'base64');
    const saltStart = 0;
    const saltSizeBytes = 8;

    const saltSize = saltSizeBytes < encryptedMessage.length ? saltSizeBytes : encryptedMessage.length;
    const encMesKernelStart = saltSizeBytes < encryptedMessage.length ? saltSizeBytes : encryptedMessage.length;
    const encMesKernelSize = saltSizeBytes < encryptedMessage.length ? (encryptedMessage.length - saltSizeBytes) : 0;

    const salt = Buffer.alloc(saltSize);
    const encryptedMessageKernel = Buffer.alloc(encMesKernelSize);

    encryptedMessage.copy(salt, 0, saltStart, saltSize);
    encryptedMessage.copy(encryptedMessageKernel, 0, encMesKernelStart, encryptedMessage.length);

    const kiv = this.getKeyIV(password || '', salt, iterations ?? this.iterations);
    const decipher = Cipher.create({ type: 'decrypt', key: Array.from(kiv[0]), iv: Array.from(kiv[1]) });

    const decrypted = decipher.update(Array.from(encryptedMessageKernel)).concat(decipher.final());

    return Buffer.from(decrypted).toString('utf-8');
  }
}
