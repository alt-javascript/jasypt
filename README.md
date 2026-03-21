# @alt-javascript/jasypt

[![NPM version][npm-image]][npm-url]
[![Build status][build-image]][build-url]
[![Downloads/month][downloads-month-image]][download-url]
[![Total downloads][downloads-image]][download-url]

A Node.js implementation of Java's [Jasypt](http://www.jasypt.org/) password-based encryption and digest utilities. Interoperable with Spring Boot applications that use `ENC(...)` encrypted configuration values.

## Quick Start

```sh
npm install @alt-javascript/jasypt
```

```js
import Jasypt from '@alt-javascript/jasypt';

const jasypt = new Jasypt();

// Encrypt and decrypt
const encrypted = jasypt.encrypt('admin', 'mySecretKey');
const decrypted = jasypt.decrypt(encrypted, 'mySecretKey');
// decrypted === 'admin'
```

## Installation

```sh
npm install @alt-javascript/jasypt
```

Or install globally for the CLI:

```sh
npm install -g @alt-javascript/jasypt
```

Requires Node.js 18 or later.

## API

### `Jasypt`

The main class provides high-level encrypt, decrypt, and digest operations.

```js
import Jasypt from '@alt-javascript/jasypt';

const jasypt = new Jasypt();
```

#### `jasypt.encrypt(message, password [, algorithm [, iterations [, salt]]])`

Encrypts a plaintext string. Returns a base64-encoded ciphertext with the salt prepended.

```js
jasypt.encrypt('admin', 'secret');
// => 'nsbC5r0ymz740/aURtuRWw=='

jasypt.encrypt('admin', 'secret', 'PBEWITHHMACSHA256ANDAES_256');
// => 'K3q8z...' (AES-256-CBC ciphertext)
```

#### `jasypt.decrypt(encryptedMessage, password [, algorithm [, iterations]])`

Decrypts a base64-encoded ciphertext. The salt is extracted from the ciphertext automatically.

```js
jasypt.decrypt('nsbC5r0ymz740/aURtuRWw==', 'secret');
// => 'admin'
```

Throws an error if the password is wrong or the ciphertext is corrupted.

#### `jasypt.digest(message [, salt [, iterations [, algorithm]]])`

Produces a one-way hash. Returns base64-encoded salt + digest bytes.

```js
const hash = jasypt.digest('admin');
```

#### `jasypt.matches(message, storedDigest [, salt [, iterations [, algorithm]]])`

Verifies a plaintext message against a stored digest. Uses constant-time comparison.

```js
const hash = jasypt.digest('admin');
jasypt.matches('admin', hash);  // => true
jasypt.matches('wrong', hash);  // => false
```

### `Encryptor`

Low-level class for direct control over encryption parameters.

```js
import Jasypt from '@alt-javascript/jasypt';
const { Encryptor } = Jasypt;

const enc = new Encryptor({
  password: 'secret',
  algorithm: 'PBEWITHHMACSHA256ANDAES_256',
  iterations: 2000,
});

const ciphertext = enc.encrypt('admin', 'secret');
const plaintext  = enc.decrypt(ciphertext, 'secret');
```

### `Digester`

Low-level class for direct control over digest parameters.

```js
import Jasypt from '@alt-javascript/jasypt';
const { Digester } = Jasypt;

const dig = new Digester({ algorithm: 'SHA-512' });
dig.setIterations(5000);
dig.setSaltSize(16);

const hash    = dig.digest('admin');
const isMatch = dig.matches('admin', hash); // => true
```

## CLI

```
Usage: jasypt [options] [command]

Commands:
  encrypt|enc <msg>            Encrypt a plaintext message
  decrypt|dec <msg>            Decrypt an encrypted message
  digest|dig <msg>             One-way digest (hash) a message
  matches|match <msg> <stored> Verify a message against a stored digest

Options:
  -v, --version  Output the version number
  -h, --help     Output usage information
```

### Encrypt and Decrypt

```sh
jasypt encrypt -p mySecretKey admin
# => nsbC5r0ymz740/aURtuRWw==

jasypt decrypt -p mySecretKey nsbC5r0ymz740/aURtuRWw==
# => admin

# Use a different algorithm
jasypt encrypt -p mySecretKey -a PBEWITHHMACSHA256ANDAES_256 admin
```

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --password <pwd>` | | Secret key (required) |
| `-a, --algorithm <algo>` | `PBEWITHMD5ANDDES` | Encryption algorithm |

### Digest and Verify

```sh
jasypt digest admin
# => base64-encoded hash

jasypt matches admin 'stored-hash-here'
# => true or false

# Custom algorithm, iterations, and salt size
jasypt digest -a SHA-512 -i 500 -s 16 admin
```

| Option | Default | Description |
|--------|---------|-------------|
| `-a, --algorithm <algo>` | `SHA-256` | Digest algorithm |
| `-i, --iterations <n>` | `1000` | Hash iterations |
| `-s, --salt-size <n>` | `8` | Salt size in bytes |

## Supported Algorithms

### Encryption

| Algorithm | Type | Description |
|-----------|------|-------------|
| `PBEWITHMD5ANDDES` | PBE1 | MD5 KDF + DES-CBC (default) |
| `PBEWITHMD5ANDTRIPLEDES` | PBE1 | MD5 KDF + 3DES-CBC |
| `PBEWITHSHA1ANDDESEDE` | PBE1 | SHA-1 KDF + 3DES-CBC |
| `PBEWITHSHA1ANDRC2_128` | PBE1 | SHA-1 KDF + RC2-CBC 128-bit |
| `PBEWITHSHA1ANDRC2_40` | PBE1 | SHA-1 KDF + RC2-CBC 40-bit |
| `PBEWITHSHA1ANDRC4_128` | PBE1 | SHA-1 KDF + RC4 128-bit |
| `PBEWITHSHA1ANDRC4_40` | PBE1 | SHA-1 KDF + RC4 40-bit |
| `PBEWITHHMACSHA1ANDAES_128` | PBE2 | PBKDF2-SHA1 + AES-128-CBC |
| `PBEWITHHMACSHA1ANDAES_256` | PBE2 | PBKDF2-SHA1 + AES-256-CBC |
| `PBEWITHHMACSHA224ANDAES_128` | PBE2 | PBKDF2-SHA224 + AES-128-CBC |
| `PBEWITHHMACSHA224ANDAES_256` | PBE2 | PBKDF2-SHA224 + AES-256-CBC |
| `PBEWITHHMACSHA256ANDAES_128` | PBE2 | PBKDF2-SHA256 + AES-128-CBC |
| `PBEWITHHMACSHA256ANDAES_256` | PBE2 | PBKDF2-SHA256 + AES-256-CBC |
| `PBEWITHHMACSHA384ANDAES_128` | PBE2 | PBKDF2-SHA384 + AES-128-CBC |
| `PBEWITHHMACSHA384ANDAES_256` | PBE2 | PBKDF2-SHA384 + AES-256-CBC |
| `PBEWITHHMACSHA512ANDAES_128` | PBE2 | PBKDF2-SHA512 + AES-128-CBC |
| `PBEWITHHMACSHA512ANDAES_256` | PBE2 | PBKDF2-SHA512 + AES-256-CBC |
| `PBEWITHHMACSHA512/224ANDAES_128` | PBE2 | PBKDF2-SHA512/224 + AES-128-CBC |
| `PBEWITHHMACSHA512/224ANDAES_256` | PBE2 | PBKDF2-SHA512/224 + AES-256-CBC |
| `PBEWITHHMACSHA512/256ANDAES_128` | PBE2 | PBKDF2-SHA512/256 + AES-128-CBC |
| `PBEWITHHMACSHA512/256ANDAES_256` | PBE2 | PBKDF2-SHA512/256 + AES-256-CBC |

**PBE1** algorithms use an iterative MD5/SHA-1 KDF (EVP_BytesToKey-style) with an 8-byte salt. RC2 and RC4 variants require the OpenSSL legacy provider.

**PBE2** algorithms use PBKDF2 with a 16-byte salt and a random 16-byte IV stored alongside the ciphertext.

### Digest

| Algorithm | Notes |
|-----------|-------|
| `MD5` | |
| `SHA-1` | |
| `SHA-224` | |
| `SHA-256` | Default |
| `SHA-384` | |
| `SHA-512` | |
| `SHA-512/224` | |
| `SHA-512/256` | |
| `SHA3-224` | |
| `SHA3-256` | |
| `SHA3-384` | |
| `SHA3-512` | |
| `MD2` | Requires OpenSSL legacy provider |

`Digester.SUPPORTED_ALGORITHMS` reflects only algorithms available in the current OpenSSL build.

## Acknowledgements

This project is a fork of [jasypt](https://www.npmjs.com/package/jasypt) by [Ricky](https://github.com/rickyes/jasypt), updated for Node.js 18+ (OpenSSL 3.0 compatibility), with additional algorithms, digest support, and an improved CLI.

## License

[MIT](LICENSE)

[npm-image]: https://img.shields.io/npm/v/%40alt-javascript%2Fjasypt.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/@alt-javascript/jasypt
[build-image]: https://github.com/alt-javascript/jasypt/actions/workflows/node.js.yml/badge.svg?branch=main
[build-url]: https://github.com/alt-javascript/jasypt/actions/workflows/node.js.yml
[downloads-month-image]: https://img.shields.io/npm/dm/%40alt-javascript%2Fjasypt.svg?style=flat-square
[download-url]: https://www.npmjs.com/package/@alt-javascript/jasypt
[downloads-image]: https://img.shields.io/npm/dt/%40alt-javascript%2Fjasypt.svg
