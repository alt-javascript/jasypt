#!/usr/bin/env node

/* eslint no-console: off */
import { createRequire } from 'module';
import program from 'commander';
import Jasypt from '../index.js';
import Digester from '../digester.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const DIGEST_ALGORITHMS = Digester.SUPPORTED_ALGORITHMS;
const DEFAULT_DIGEST_ALGORITHM = 'SHA-256';

const ALGORITHMS = [
  'PBEWITHMD5ANDDES',
  'PBEWITHMD5ANDTRIPLEDES',
  'PBEWITHSHA1ANDDESEDE',
];

const DEFAULT_ALGORITHM = 'PBEWITHMD5ANDDES';

const jasypt = new Jasypt();

const setPassword = (value) => {
  jasypt.setPassword(value);
};

const setAlgorithm = (value) => {
  if (!ALGORITHMS.includes(value)) {
    console.error(`Unknown algorithm: ${value}`);
    console.error(`Supported algorithms: ${ALGORITHMS.join(', ')}`);
    process.exit(1);
  }
  jasypt.setAlgorithm(value);
};

program
  .version(pkg.version, '-v, --version')
  .option('-p, --password <pwd>', 'The secret key', setPassword)
  .option('-a, --algorithm <algo>', `Encryption algorithm (default: ${DEFAULT_ALGORITHM})`, setAlgorithm)
  .on('--help', function() {
    console.log('');
    console.log('Supported algorithms:');
    ALGORITHMS.forEach(a => {
      const marker = a === DEFAULT_ALGORITHM ? ' (default)' : '';
      console.log(`  ${a}${marker}`);
    });
    console.log('');
    console.log('Examples:');
    console.log('');
    console.log('  $ jasypt -p 0x1995 encrypt admin');
    console.log('  $ jasypt -p 0x1995 decrypt nsbC5r0ymz740/aURtuRWw==');
    console.log('  $ jasypt -p 0x1995 -a PBEWITHMD5ANDTRIPLEDES encrypt admin');
    console.log('');
    console.log('  $ jasypt digest admin');
    console.log('  $ jasypt digest -a SHA-512 -i 500 -s 16 admin');
    console.log('  $ jasypt matches admin 6N0oHJb7...==');
    console.log('  $ jasypt matches -a SHA-512 -i 500 -s 16 admin 6N0oHJb7...==');
  });

program
  .command('encrypt <msg>')
  .alias('enc')
  .description('Encrypt a plaintext message')
  .action((msg) => {
    console.log(jasypt.encrypt(msg));
  });

program
  .command('decrypt <msg>')
  .alias('dec')
  .description('Decrypt an encrypted message')
  .action((msg) => {
    console.log(jasypt.decrypt(msg));
  });

program
  .command('digest <msg>')
  .alias('dig')
  .description('One-way digest (hash) a message')
  .option('-a, --algorithm <algo>', `Digest algorithm (default: ${DEFAULT_DIGEST_ALGORITHM})`, DEFAULT_DIGEST_ALGORITHM)
  .option('-i, --iterations <n>', 'Hash iterations', parseInt, 1000)
  .option('-s, --salt-size <n>', 'Salt size in bytes', parseInt, 8)
  .on('--help', function() {
    console.log('');
    console.log('Supported digest algorithms:');
    DIGEST_ALGORITHMS.forEach(a => {
      const marker = a === DEFAULT_DIGEST_ALGORITHM ? ' (default)' : '';
      console.log(`  ${a}${marker}`);
    });
  })
  .action(function(msg, cmd) {
    if (!DIGEST_ALGORITHMS.includes(cmd.algorithm.toUpperCase())) {
      console.error(`Unknown digest algorithm: ${cmd.algorithm}`);
      console.error(`Supported: ${DIGEST_ALGORITHMS.join(', ')}`);
      process.exit(1);
    }
    const digester = new Digester();
    digester.setAlgorithm(cmd.algorithm);
    digester.setIterations(cmd.iterations);
    digester.setSaltSize(cmd.saltSize);
    console.log(digester.digest(msg));
  });

program
  .command('matches <msg> <stored>')
  .alias('match')
  .description('Verify a message against a stored digest')
  .option('-a, --algorithm <algo>', `Digest algorithm (default: ${DEFAULT_DIGEST_ALGORITHM})`, DEFAULT_DIGEST_ALGORITHM)
  .option('-i, --iterations <n>', 'Hash iterations', parseInt, 1000)
  .option('-s, --salt-size <n>', 'Salt size in bytes', parseInt, 8)
  .action(function(msg, stored, cmd) {
    if (!DIGEST_ALGORITHMS.includes(cmd.algorithm.toUpperCase())) {
      console.error(`Unknown digest algorithm: ${cmd.algorithm}`);
      console.error(`Supported: ${DIGEST_ALGORITHMS.join(', ')}`);
      process.exit(1);
    }
    const digester = new Digester();
    digester.setAlgorithm(cmd.algorithm);
    digester.setIterations(cmd.iterations);
    digester.setSaltSize(cmd.saltSize);
    console.log(digester.matches(msg, stored));
  });

program.parse(process.argv);

if (process.argv.length === 2) {
  program.help();
}
