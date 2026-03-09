## @alt-javascript/jasypt

[![NPM version][npm-image]][npm-url]
[![build status][build-image]][build-url]
[![npm downloads/month][downloads-month-image]][download-url]
[![npm downloads][downloads-image]][download-url]


[npm-image]: https://img.shields.io/npm/v/%40alt-javascript%2Fjasypt.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/@alt-javascript/jasypt
[build-image]: https://github.com/alt-javascript/jasypt/actions/workflows/node.js.yml/badge.svg?branch=master
[build-url]: https://github.com/alt-javascript/jasypt
[downloads-month-image]: https://img.shields.io/npm/dm/%40alt-javascript%2Fjasypt.svg?style=flat-square
[download-url]: https://www.npmjs.com/package/@alt-javascript/jasypt
[downloads-image]: https://img.shields.io/npm/dt/%40alt-javascript%2Fjasypt.svg

Jasypt (Java) clone for Node.js

#### Background
`Spring Boot` integrates `jasypt` to encrypt configuration values. `@alt-javascript/Jasypt.js` exists to provide a compatible implementation for Node.js.

#### Usage
**`SDK`**
``` js
import Jasypt from '@alt-javascript/jasypt';

const jasypt = new Jasypt();
// encrypt
const encryptMsg = jasypt.encrypt('admin','G0CvDz7oJn60');
// decrypt
const decryptMsg = jasypt.decrypt(encryptMsg,'G0CvDz7oJn60');
```

**`Digester SDK`**
``` js
import Jasypt from '@alt-javascript/jasypt';

const jasypt = new Jasypt();
// digest (one-way hash)
const stored = jasypt.digest('admin');
// verify
const isMatch = jasypt.matches('admin', stored); // true
```

**`Command line`**
``` sh
$ jasypt --help

Usage: jasypt [options] [command]

Options:
  -v, --version           output the version number
  -p, --password <pwd>    The secret key
  -a, --algorithm <algo>  Encryption algorithm (default: PBEWITHMD5ANDDES)
  -h, --help              output usage information

Commands:
  encrypt|enc <msg>       Encrypt a plaintext message
  decrypt|dec <msg>       Decrypt an encrypted message
  digest|dig <msg>        One-way digest (hash) a message
  matches|match <msg> <stored>  Verify a message against a stored digest

Supported algorithms:

  encrypt/decrypt:
  
  PBEWITHMD5ANDDES (default)
  PBEWITHMD5ANDTRIPLEDES
  PBEWITHSHA1ANDDESEDE
  PBEWITHSHA1ANDRC2_128
  PBEWITHSHA1ANDRC2_40
  PBEWITHSHA1ANDRC4_128
  PBEWITHSHA1ANDRC4_40
  PBEWITHHMACSHA1ANDAES_128
  PBEWITHHMACSHA1ANDAES_256
  PBEWITHHMACSHA224ANDAES_128
  PBEWITHHMACSHA224ANDAES_256
  PBEWITHHMACSHA256ANDAES_128
  PBEWITHHMACSHA256ANDAES_256
  PBEWITHHMACSHA384ANDAES_128
  PBEWITHHMACSHA384ANDAES_256
  PBEWITHHMACSHA512/224ANDAES_128
  PBEWITHHMACSHA512/224ANDAES_256
  PBEWITHHMACSHA512/256ANDAES_128
  PBEWITHHMACSHA512/256ANDAES_256
  PBEWITHHMACSHA512ANDAES_128
  PBEWITHHMACSHA512ANDAES_256

  digest/matches:
  
  MD2
  MD5
  SHA-1 
  SHA-224
  SHA-256
  SHA-384
  SHA-512
  SHA-512/224
  SHA-512/256
  SHA3-224
  SHA3-256
  SHA3-384
  SHA3-512
Examples:

  $ jasypt encrypt -p 0x1995 admin
  $ jasypt decrypt -p 0x1995 nsbC5r0ymz740/aURtuRWw==
  $ jasypt encrypt -p 0x1995 -a PBEWITHHMACSHA256ANDAES_256 admin

  $ jasypt digest admin
  $ jasypt digest -a SHA-512 -i 500 -s 16 admin
  $ jasypt matches admin 6N0oHJb7...==
  $ jasypt matches -a SHA-512 -i 500 -s 16 admin 6N0oHJb7...==
  
```

**`Encrypt command options`**

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --password <pwd>` | | Secret key |
| `-a, --algorithm <algo>` | `PBEWITHMD5ANDDES` | Encryption algorithm (see supported list above) |

**`Digest command options`**

| Option | Default | Description |
|--------|---------|-------------|
| `-a, --algorithm <algo>` | `SHA-256` | Digest algorithm (see supported list below) |
| `-i, --iterations <n>` | `1000` | Number of hash iterations |
| `-s, --salt-size <n>` | `8` | Salt size in bytes |

**`Supported encryption algorithms`**

| Algorithm | Type | Notes |
|-----------|------|-------|
| `PBEWITHMD5ANDDES` | PBE1 | Default; MD5 KDF + DES-CBC |
| `PBEWITHMD5ANDTRIPLEDES` | PBE1 | MD5 KDF + 3DES-CBC |
| `PBEWITHSHA1ANDDESEDE` | PBE1 | SHA-1 KDF + 3DES-CBC |
| `PBEWITHSHA1ANDRC2_128` | PBE1 | SHA-1 KDF + RC2-CBC 128-bit; requires OpenSSL legacy provider |
| `PBEWITHSHA1ANDRC2_40` | PBE1 | SHA-1 KDF + RC2-CBC 40-bit; requires OpenSSL legacy provider |
| `PBEWITHSHA1ANDRC4_128` | PBE1 | SHA-1 KDF + RC4 128-bit; requires OpenSSL legacy provider |
| `PBEWITHSHA1ANDRC4_40` | PBE1 | SHA-1 KDF + RC4 40-bit; requires OpenSSL legacy provider |
| `PBEWITHHMACSHA1ANDAES_128` | PBE2 | PBKDF2-SHA1 + AES-128-CBC |
| `PBEWITHHMACSHA1ANDAES_256` | PBE2 | PBKDF2-SHA1 + AES-256-CBC |
| `PBEWITHHMACSHA224ANDAES_128` | PBE2 | PBKDF2-SHA224 + AES-128-CBC |
| `PBEWITHHMACSHA224ANDAES_256` | PBE2 | PBKDF2-SHA224 + AES-256-CBC |
| `PBEWITHHMACSHA256ANDAES_128` | PBE2 | PBKDF2-SHA256 + AES-128-CBC |
| `PBEWITHHMACSHA256ANDAES_256` | PBE2 | PBKDF2-SHA256 + AES-256-CBC |
| `PBEWITHHMACSHA384ANDAES_128` | PBE2 | PBKDF2-SHA384 + AES-128-CBC |
| `PBEWITHHMACSHA384ANDAES_256` | PBE2 | PBKDF2-SHA384 + AES-256-CBC |
| `PBEWITHHMACSHA512/224ANDAES_128` | PBE2 | PBKDF2-SHA512/224 + AES-128-CBC |
| `PBEWITHHMACSHA512/224ANDAES_256` | PBE2 | PBKDF2-SHA512/224 + AES-256-CBC |
| `PBEWITHHMACSHA512/256ANDAES_128` | PBE2 | PBKDF2-SHA512/256 + AES-128-CBC |
| `PBEWITHHMACSHA512/256ANDAES_256` | PBE2 | PBKDF2-SHA512/256 + AES-256-CBC |
| `PBEWITHHMACSHA512ANDAES_128` | PBE2 | PBKDF2-SHA512 + AES-128-CBC |
| `PBEWITHHMACSHA512ANDAES_256` | PBE2 | PBKDF2-SHA512 + AES-256-CBC |

> **PBE1** uses an iterative MD5/SHA1 KDF (EVP_BytesToKey-style) with an 8-byte salt.
> **PBE2** uses PBKDF2 with a 16-byte salt and a random 16-byte IV stored alongside the ciphertext.

**`Supported digest algorithms`**

| Algorithm | Notes |
|-----------|-------|
| `MD2` | Requires OpenSSL legacy provider |
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

`Digester.SUPPORTED_ALGORITHMS` reflects only algorithms available in the current OpenSSL build.

This project is a fork (clone) of [jasypt @ npmjs.com](https://www.npmjs.com/package/jasypt) | [jasypt @ github.com/rickyes](https://github.com/rickyes/jasypt) by
[Ricky泽阳](mailtto://mail@zhoumq.cn), updated to work with Node LTS (post v16) with additional features, and improved CLI options.
