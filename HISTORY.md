1.0.1 / 2026-03-10
==================

* CLI help includes digest algorithms.

1.0.0 / 2026-03-10 
==================
  
  * Initial fork - @craigparra, updates with Claude: 
    * Upgrade to LTS 24 and fix crypto incompatibility failures.
    * Convert CommonJS to ES Modules
    * Tidy package.json, and revise authorship and contributors.
    * Translate comments to simple English
    * Add a switch for selecting algorithm, and add support for variant algorithms
    * Change -e / -d options to commands encrypt|enc and decrypt|dec
    * Add digest & match commands, with options.
    * Remove decryptConfig operation and test; is a separate concern, handled in alt-javascript/config
    
