
export type EncryptionAlgorithm =
  | 'PBEWITHMD5ANDDES'
  | 'PBEWITHMD5ANDTRIPLEDES'
  | 'PBEWITHSHA1ANDDESEDE';

export type DigestAlgorithm =
  | 'MD5'
  | 'SHA-1'
  | 'SHA-224'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512';

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

  encrypt(message: string, password: string, algorithm?: EncryptionAlgorithm, iterations?: number, salt?: Buffer): string | null;
  decrypt(encryptedMessage: string, password: string, algorithm?: EncryptionAlgorithm, iterations?: number, salt?: Buffer): string | null;
  digest(message: string, password?: string, iterations?: number): string | null;
}

export default Jasypt;