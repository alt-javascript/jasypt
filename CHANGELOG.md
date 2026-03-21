# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-03-21

### Fixed

- CLI `decrypt` command now prints a user-friendly error instead of crashing with a stack trace when given a wrong password or corrupted ciphertext.

### Changed

- Rewrote README.md with structured npm-ready documentation: quick start, API reference, CLI usage, algorithm tables, and badges.

## [1.0.1] - 2026-03-10

### Added

- `Digester` class (`digester.js`) for one-way message digesting with configurable algorithm, salt size, and iterations.
- CLI `digest` and `matches` commands for hashing and verifying messages.
- Digest algorithms: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512.
- `-a, --algorithm` option on CLI `encrypt` and `decrypt` commands.
- `encrypt` and `decrypt` aliases (`enc`, `dec`) as CLI shorthand.
- CLI help now lists supported digest algorithms.

### Changed

- CLI switched from `-e`/`-d` options to `encrypt`/`decrypt` subcommands.

## [1.0.0] - 2026-03-08

### Added

- PBE2 encryption algorithms: PBEWITHHMACSHA1ANDAES_128, PBEWITHHMACSHA1ANDAES_256, PBEWITHHMACSHA224ANDAES_128, PBEWITHHMACSHA224ANDAES_256, PBEWITHHMACSHA256ANDAES_128, PBEWITHHMACSHA256ANDAES_256, PBEWITHHMACSHA384ANDAES_128, PBEWITHHMACSHA384ANDAES_256, PBEWITHHMACSHA512ANDAES_128, PBEWITHHMACSHA512ANDAES_256, PBEWITHHMACSHA512/224ANDAES_128, PBEWITHHMACSHA512/224ANDAES_256, PBEWITHHMACSHA512/256ANDAES_128, PBEWITHHMACSHA512/256ANDAES_256.
- PBE1 algorithms: PBEWITHMD5ANDTRIPLEDES, PBEWITHSHA1ANDDESEDE, PBEWITHSHA1ANDRC2_128, PBEWITHSHA1ANDRC2_40, PBEWITHSHA1ANDRC4_128, PBEWITHSHA1ANDRC4_40.
- Generalised EVP_BytesToKey-compatible KDF supporting multi-block key derivation.
- TypeScript type declarations (`index.d.ts`).

### Changed

- Forked and refactored from original `jasypt` package.
- Converted from CommonJS to ES Modules.
- Replaced `crypto.createCipheriv('des', ...)` with `des.js` for OpenSSL 3.0 / Node.js 18+ compatibility.
- Upgraded `tap` from v14 to v21 for Node.js 24 compatibility.
- Translated all JSDoc comments and README content from Chinese to English.
- Revised `package.json` authorship and contributors.

### Removed

- `decryptConfig` operation and tests (handled separately in `@alt-javascript/config`).

[Unreleased]: https://github.com/alt-javascript/jasypt/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/alt-javascript/jasypt/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/alt-javascript/jasypt/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/alt-javascript/jasypt/releases/tag/v1.0.0
