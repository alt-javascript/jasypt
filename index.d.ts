
export type EncryptionAlgorithm =
  // PBE1: iterative-hash KDF + DES/3DES
  | 'PBEWITHMD5ANDDES'
  | 'PBEWITHMD5ANDTRIPLEDES'
  | 'PBEWITHSHA1ANDDESEDE'
  // PBE1N: iterative-hash KDF + RC2/RC4 (requires OpenSSL legacy provider)
  | 'PBEWITHSHA1ANDRC2_128'
  | 'PBEWITHSHA1ANDRC2_40'
  | 'PBEWITHSHA1ANDRC4_128'
  | 'PBEWITHSHA1ANDRC4_40'
  // PBE2: PBKDF2 + AES-CBC
  | 'PBEWITHHMACSHA1ANDAES_128'
  | 'PBEWITHHMACSHA1ANDAES_256'
  | 'PBEWITHHMACSHA224ANDAES_128'
  | 'PBEWITHHMACSHA224ANDAES_256'
  | 'PBEWITHHMACSHA256ANDAES_128'
  | 'PBEWITHHMACSHA256ANDAES_256'
  | 'PBEWITHHMACSHA384ANDAES_128'
  | 'PBEWITHHMACSHA384ANDAES_256'
  | 'PBEWITHHMACSHA512/224ANDAES_128'
  | 'PBEWITHHMACSHA512/224ANDAES_256'
  | 'PBEWITHHMACSHA512/256ANDAES_128'
  | 'PBEWITHHMACSHA512/256ANDAES_256'
  | 'PBEWITHHMACSHA512ANDAES_128'
  | 'PBEWITHHMACSHA512ANDAES_256';

export type DigestAlgorithm =
  | 'MD2'
  | 'MD5'
  | 'SHA-1'
  | 'SHA-224'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA-512/224'
  | 'SHA-512/256'
  | 'SHA3-224'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512';

export declare class Encryptor {
  constructor(opts?: {
    algorithm?: EncryptionAlgorithm;
    salt?: Buffer;
    iterations?: number;
  });

  setAlgorithm(algorithm: EncryptionAlgorithm): void;
  setSalt(salt: Buffer): void;
  setIterations(iterations: number): void;

  encrypt(payload: string, password: string, salt?: Buffer, iterations?: number): string;
  decrypt(payload: string, password: string, iterations?: number): string;
}

export declare class Digester {
  static readonly SUPPORTED_ALGORITHMS: DigestAlgorithm[];

  constructor();

  setAlgorithm(algorithm: DigestAlgorithm): void;
  setSaltSize(size: number): void;
  setIterations(iterations: number): void;

  digest(message: string): string;
  matches(message: string, storedDigest: string): boolean;
}

export declare class Jasypt {
  static Encryptor: typeof Encryptor;
  static Digester: typeof Digester;

  constructor();

   encrypt(message: string, password?: string, algorithm?: EncryptionAlgorithm, iterations?: number, salt?: Buffer): string | null;
   decrypt(encryptedMessage: string, password?: string, algorithm?: EncryptionAlgorithm, iterations?: number): string | null;
   digest(message: string, iterations?: number): string | null;
}

export default Jasypt;
