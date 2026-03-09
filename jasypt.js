import assert from 'assert';
import Encryptor from './encryptor.js';
import {isEmpty} from './util.js';
import Digester from "./digester.js";

export default class Jasypt {

  constructor() {
  }

  /**
   * Encrypt a plaintext message
   * @param {String} message text to encrypt
   * @param {String} password password for encryption
   * @param {String} algorithm algorithm for encryption
   * @param {String} salt random salt for encryption
   * @param {Integer} iterations number of iterations encryption
   */
  encrypt(message, password, algorithm, iterations, salt) {
    if (isEmpty(message)) {
      return null;
    }
    const encryptor = new Encryptor({ password : password, algorithm :algorithm, salt:salt, iterations:iterations });
    return encryptor.encrypt(message, password, iterations, salt);
  }

  /**
   * Decrypt an encrypted message
   * @param {String} encryptedMessage text to decrypt
   * @param {String} password password for decrypt
   * @param {String} algorithm algorithm for decryption
   * @param {String} salt random salt for decryption
   * @param {Integer} iterations number of iterations decryption
   */
  decrypt(encryptedMessage,password, algorithm, iterations, salt) {
    if (isEmpty(encryptedMessage)) {
      return null;
    }
    const encryptor = new Encryptor({ password : password, algorithm :algorithm, salt:salt, iterations:iterations });
    return encryptor.decrypt(encryptedMessage, password, iterations);
  }

  /**
   * One-way digest a plaintext message
   * @param {String} message text to digest
   * @param {Integer} iterations number of hash iterations
   * @param {String} salt optional fixed salt (overrides this.salt)
   * @param {Number} iterations optional iteration count
   * @param {String} algorithm optional digest algorithm
   */
  digest(message, salt, iterations, algorithm) {
    if (isEmpty(message)) {
      return null;
    }
    const digester = new Digester({algorithm:algorithm});
    return digester.digest(message,salt, iterations);
  }

  /**
   * Verify a plaintext message against a stored digest
   * @param {String} message plaintext to verify
   * @param {String} storedDigest base64-encoded stored digest
   * @param {String} salt optional fixed salt (overrides this.salt)
   * @param {Number} iterations optional iteration count
   * @param {String} algorithm optional digest algorithm
   */
  matches(message, storedDigest, salt, iterations, algorithm) {
    if (isEmpty(message)) {
      return null;
    }
    return new Digester({algorithm:algorithm}).matches(message, storedDigest, salt, iterations);
  }

}
