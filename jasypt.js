import crypto from 'crypto';
import assert from 'assert';
import Encryptor from './encryptor.js';
import { isEmpty, isType } from './util.js';
import cacher from './cache.js';

export default class Jasypt {

  constructor(opts = {}) {
    this._encryptor = new Encryptor();
    this._encryptor.setAlgorithm('PBEWithMD5AndDES');
    this.salt = opts.salt || crypto.randomBytes(8);
    this.iterations = opts.iterations || 1000;
    this.password = '';
  }

  getCacheKey(key) {
    return `${this.salt}_${this.iterations}_${this.password}_${key}`;
  }

  /**
   * Set the encryption algorithm
   * @param {String} algorithm algorithm name
   */
  setAlgorithm(algorithm) {
    this._encryptor.setAlgorithm(algorithm);
  }

  /**
   * Set the encryption password
   * @param {String} password secret key
   */
  setPassword(password) {
    assert(!isEmpty(password), 'Password cannot be set empty');
    this.password = password;
  }

  /**
   * Encrypt a plaintext message
   * @param {String} message text to encrypt
   */
  encrypt(message) {
    if (isEmpty(message)) {
      return null;
    }
    return this._encryptor.encrypt(message, this.password, this.salt, this.iterations);
  }

  /**
   * Decrypt an encrypted message
   * @param {String} encryptedMessage text to decrypt
   */
  decrypt(encryptedMessage) {
    if (isEmpty(encryptedMessage)) {
      return null;
    }

    const cacheKey = this.getCacheKey(encryptedMessage);
    if (cacher.has(cacheKey)) return cacher.get(cacheKey);

    const value = this._encryptor.decrypt(encryptedMessage, this.password, this.iterations);
    cacher.set(cacheKey, value);

    return value;
  }

  /**
   * Recursively decrypt all ENC(xxx) values in a config object
   * @param {Object} obj config object
   */
  decryptConfig(obj) {
    if (!isType('Object', obj)) {
      return;
    }
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (isType('Object', value)) {
          this.decryptConfig(value);
        } else if (isType('String', value)) {
          if (value.indexOf('ENC(') === 0 && value.lastIndexOf(')') === value.length - 1) {
            const encryptMsg = value.substring(4, value.length - 1);
            obj[key] = this.decrypt(encryptMsg);
          }
        } else if (isType('Array', value)) {
          for (const item of value) {
            if (isType('Object', item)) {
              this.decryptConfig(item);
            }
          }
        } else {
          continue;
        }
      }
    }
  }
}
