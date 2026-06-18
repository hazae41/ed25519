import { Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, load, Memory } from "@hazae41/ed25519-wasm";

await load()

export class SecretKey {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: Ed25519SigningKey
  ) { }

  /**
   * Generate a random secret key
   * @returns 
   */
  static random(): SecretKey {
    return new SecretKey(new Ed25519SigningKey())
  }

  /**
   * Import from 32 bytes
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): SecretKey {
    return new SecretKey(Ed25519SigningKey.from_bytes(new Memory(key)))
  }

  /**
   * Export to 32 bytes
   * @returns 
   */
  export(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.inner.to_bytes().bytes)
  }

  /**
   * Publish this secret key to a public key
   * @returns 
   */
  publish(): PublicKey {
    return new PublicKey(this.inner.publish())
  }

  /**
   * Sign a message (any size)
   * @param message 
   * @returns 
   */
  sign(message: Uint8Array): Signature {
    return new Signature(this.inner.sign(new Memory(message)))
  }

}

export class PublicKey {

  constructor(
    readonly inner: Ed25519VerifyingKey
  ) { }

  /**
   * Import from 32 bytes
   * @param key 
   * @returns 
   */
  static import(key: Uint8Array): PublicKey {
    return new PublicKey(Ed25519VerifyingKey.from_bytes(new Memory(key)))
  }

  /**
   * Export to 32 bytes
   * @returns 
   */
  export(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.inner.to_bytes().bytes)
  }

  /**
   * Verify a message (any size) with a signature
   * @param message 
   * @param signature 
   * @returns 
   */
  verify(message: Uint8Array, signature: Signature): boolean {
    return this.inner.verify(new Memory(message), signature.inner)
  }

}

export class Signature {

  /**
   * Do not use
   * @param inner 
   */
  constructor(
    readonly inner: Ed25519Signature
  ) { }

  /**
   * Import from 64 bytes
   * @param rs 
   * @returns 
   */
  static import(rs: Uint8Array): Signature {
    return new Signature(Ed25519Signature.from_bytes(new Memory(rs)))
  }

  /**
   * Export to 64 bytes
   * @returns 
   */
  export(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.inner.to_bytes().bytes)
  }

}