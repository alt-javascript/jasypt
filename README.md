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
// set password
jasypt.setPassword('G0CvDz7oJn60');
// encrypt
const encryptMsg = jasypt.encrypt('admin');
// decrypt
const decryptMsg = jasypt.decrypt(encryptMsg);
```

**`Digester SDK`**
``` js
import Jasypt from '@alt-javascript/jasypt';

const { Digester } = Jasypt;
const digester = new Digester();
// digest (one-way hash)
const stored = digester.digest('admin');
// verify
const isMatch = digester.matches('admin', stored); // true
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
  PBEWITHMD5ANDDES (default)
  PBEWITHMD5ANDTRIPLEDES
  PBEWITHSHA1ANDDESEDE

Examples:

  $ jasypt -p 0x1995 encrypt admin
  $ jasypt -p 0x1995 decrypt nsbC5r0ymz740/aURtuRWw==
  $ jasypt -p 0x1995 -a PBEWITHMD5ANDTRIPLEDES encrypt admin

  $ jasypt digest admin
  $ jasypt digest -a SHA-512 -i 500 -s 16 admin
  $ jasypt matches admin 6N0oHJb7...==
  $ jasypt matches -a SHA-512 -i 500 -s 16 admin 6N0oHJb7...==
```

**`Digest command options`**

| Option | Default | Description |
|--------|---------|-------------|
| `-a, --algorithm <algo>` | `SHA-256` | Digest algorithm (`MD5`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`) |
| `-i, --iterations <n>` | `1000` | Number of hash iterations |
| `-s, --salt-size <n>` | `8` | Salt size in bytes |

This project is a fork (clone) of [jasypt @ npmjs.com](https://www.npmjs.com/package/jasypt) | [jasypt @ github.com/rickyes](https://github.com/rickyes/jasypt) by
[Ricky泽阳](mailtto://mail@zhoumq.cn), updated to work with Node LTS (post v16) with additional features, and improved CLI options.
