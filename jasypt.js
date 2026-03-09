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
   * Digest a plaintext message
   * @param {String} message text to encrypt
   * @param {String} password password for encrypt
   * @param {Integer} iterations number of iterations encrypt
   */
  digest(message, password, iterations) {
    if (isEmpty(message)) {
      return null;
    }
    const digester = new Digester();
    return digester.digest(message, password ?? this.password, iterations ?? this.iterations);
  }

}
