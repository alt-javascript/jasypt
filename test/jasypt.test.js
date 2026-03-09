import { test } from 'tap';
import Jasypt from '../index.js';
import Encryptor from "../encryptor.js";

const Digester = Jasypt.Digester;
const password = 'G0CvDz7oJn60';
const message = 'admin';
const decryptMessage = 'c0KA89TBZ6TbLn7E6RIiFQ==';

test('encrypt', t => {
  const jasypt = new Jasypt();
  const encryptMsg = jasypt.encrypt('',password);
  t.equal(encryptMsg, null);
  jasypt.encrypt('a',password);
  t.end();
});

test('decrypt', t => {
  const jasypt = new Jasypt();

  let decryptMsg = '';
  decryptMsg = jasypt.decrypt(null);
  t.equal(decryptMsg, null);
  decryptMsg = jasypt.decrypt(decryptMessage,password);
  t.equal(decryptMsg, message);
  t.end();
});

test('encrypt & decrypt', t => {
  const jasypt = new Jasypt();

  const encryptMsg = jasypt.encrypt(message,password);
  const decryptMsg = jasypt.decrypt(encryptMsg,password);
  t.equal(decryptMsg, message);
  t.end();
});

test('PBEWITHMD5ANDTRIPLEDES encrypt & decrypt', t => {
  const jasypt = new Jasypt();

  const encryptMsg = jasypt.encrypt(message,password,'PBEWITHMD5ANDTRIPLEDES');
  const decryptMsg = jasypt.decrypt(encryptMsg,password,'PBEWITHMD5ANDTRIPLEDES');
  t.equal(decryptMsg, message);
  t.end();
});

test('PBEWITHSHA1ANDDESEDE encrypt & decrypt', t => {
  const jasypt = new Jasypt();
  const encryptMsg = jasypt.encrypt(message,password,'PBEWITHSHA1ANDDESEDE');
  const decryptMsg = jasypt.decrypt(encryptMsg,password,'PBEWITHSHA1ANDDESEDE');
  t.equal(decryptMsg, message);
  t.end();
});

test('unsupported algorithm throws', t => {
  const encryptor = new Encryptor();
  t.throws(() => encryptor.setAlgorithm('INVALID'), /Unsupported algorithm/);
  t.end();
});

test('digester: SHA-256 digest and matches', t => {
  const digester = new Digester();
  const stored = digester.digest('admin');
  t.equal(digester.matches('admin', stored), true);
  t.equal(digester.matches('wrong', stored), false);
  t.end();
});

test('digester: MD5 algorithm', t => {
  const digester = new Digester();
  digester.setAlgorithm('MD5');
  const stored = digester.digest('admin');
  t.equal(digester.matches('admin', stored), true);
  t.end();
});

test('digester: SHA-512 with custom salt size and iterations', t => {
  const digester = new Digester();
  digester.setAlgorithm('SHA-512');
  digester.setSaltSize(16);
  digester.setIterations(500);
  const stored = digester.digest('admin');
  t.equal(digester.matches('admin', stored), true);
  t.equal(digester.matches('other', stored), false);
  t.end();
});

test('digester: unsupported algorithm throws', t => {
  const digester = new Digester();
  t.throws(() => digester.setAlgorithm('AES'), /Unsupported digest algorithm/);
  t.end();
});
