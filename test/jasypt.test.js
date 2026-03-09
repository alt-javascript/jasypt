import crypto from 'crypto';
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

// AES algorithms (PBKDF2-based)
const aesAlgorithms = [
  'PBEWITHHMACSHA1ANDAES_128',
  'PBEWITHHMACSHA1ANDAES_256',
  'PBEWITHHMACSHA224ANDAES_128',
  'PBEWITHHMACSHA224ANDAES_256',
  'PBEWITHHMACSHA256ANDAES_128',
  'PBEWITHHMACSHA256ANDAES_256',
  'PBEWITHHMACSHA384ANDAES_128',
  'PBEWITHHMACSHA384ANDAES_256',
  'PBEWITHHMACSHA512ANDAES_128',
  'PBEWITHHMACSHA512ANDAES_256',
];

for (const algo of aesAlgorithms) {
  test(`${algo} encrypt & decrypt`, t => {
    const jasypt = new Jasypt();
    const encryptMsg = jasypt.encrypt(message, password, algo);
    const decryptMsg = jasypt.decrypt(encryptMsg, password, algo);
    t.equal(decryptMsg, message);
    t.end();
  });
}

// SHA-512/224 and SHA-512/256 variants — skip if PBKDF2 digest unavailable
const sha512TruncAlgorithms = [
  ['PBEWITHHMACSHA512/224ANDAES_128', 'sha512-224'],
  ['PBEWITHHMACSHA512/224ANDAES_256', 'sha512-224'],
  ['PBEWITHHMACSHA512/256ANDAES_128', 'sha512-256'],
  ['PBEWITHHMACSHA512/256ANDAES_256', 'sha512-256'],
];

for (const [algo, hmac] of sha512TruncAlgorithms) {
  let available = false;
  try { crypto.pbkdf2Sync('x', 'y', 1, 16, hmac); available = true; } catch {}

  if (available) {
    test(`${algo} encrypt & decrypt`, t => {
      const jasypt = new Jasypt();
      const encryptMsg = jasypt.encrypt(message, password, algo);
      const decryptMsg = jasypt.decrypt(encryptMsg, password, algo);
      t.equal(decryptMsg, message);
      t.end();
    });
  } else {
    test(`${algo} skipped (${hmac} unavailable in this OpenSSL build)`, t => {
      t.pass('skipped');
      t.end();
    });
  }
}

// RC2/RC4 — skip if cipher unavailable (deprecated in OpenSSL 3.x legacy provider)
const legacyCipherAlgorithms = [
  ['PBEWITHSHA1ANDRC2_128', 'rc2-cbc'],
  ['PBEWITHSHA1ANDRC2_40',  'rc2-40-cbc'],
  ['PBEWITHSHA1ANDRC4_128', 'rc4'],
  ['PBEWITHSHA1ANDRC4_40',  'rc4-40'],
];

for (const [algo, cipher] of legacyCipherAlgorithms) {
  const available = crypto.getCiphers().includes(cipher);

  if (available) {
    test(`${algo} encrypt & decrypt`, t => {
      const jasypt = new Jasypt();
      const encryptMsg = jasypt.encrypt(message, password, algo);
      const decryptMsg = jasypt.decrypt(encryptMsg, password, algo);
      t.equal(decryptMsg, message);
      t.end();
    });
  } else {
    test(`${algo} skipped (${cipher} unavailable in this OpenSSL build)`, t => {
      t.pass('skipped');
      t.end();
    });
  }
}

// Digester tests
const allDigestAlgorithms = [
  'MD2', 'MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512',
  'SHA-512/224', 'SHA-512/256',
  'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
];

for (const algo of allDigestAlgorithms) {
  const available = Digester.SUPPORTED_ALGORITHMS.includes(algo);

  if (available) {
    test(`digester: ${algo} digest and matches`, t => {
      const digester = new Digester();
      digester.setAlgorithm(algo);
      const stored = digester.digest('admin');
      t.equal(digester.matches('admin', stored), true);
      t.equal(digester.matches('wrong', stored), false);
      t.end();
    });
  } else {
    test(`digester: ${algo} skipped (unavailable in this OpenSSL build)`, t => {
      t.pass('skipped');
      t.end();
    });
  }
}

test('digester: default SHA-256 digest and matches', t => {
  const digester = new Digester();
  const stored = digester.digest('admin');
  t.equal(digester.matches('admin', stored), true);
  t.equal(digester.matches('wrong', stored), false);
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