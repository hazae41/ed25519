import { Cursor, CursorWriteError } from "@hazae41/cursor"
import { Ok, Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"
import { fromSafe } from "./safe.js"

export const global: {
  value: Adapter
} = {
  value: fromSafe()
}

export interface Copiable {
  readonly bytes: Uint8Array

  [Symbol.dispose](): void

  copy(): Uint8Array

  trySize(): Result<number, never>

  tryWrite(cursor: Cursor): Result<void, CursorWriteError>
}

export class Copied implements Copiable {

  /**
   * A copiable that's already copied
   * @param bytes 
   */
  constructor(
    readonly bytes: Uint8Array
  ) { }

  [Symbol.dispose]() { }

  copy() {
    return this.bytes
  }

  trySize(): Result<number, never> {
    return new Ok(this.bytes.length)
  }

  tryWrite(cursor: Cursor): Result<void, CursorWriteError> {
    return cursor.tryWrite(this.bytes)
  }

}

export interface Signature extends Disposable {
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface PublicKey extends Disposable {
  tryVerify(payload: Uint8Array, signature: Signature): Promiseable<Result<boolean, CryptoError>>
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface PrivateKey extends Disposable {
  tryPublic(): Promiseable<Result<PublicKey, CryptoError>>
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<PublicKey, CryptoError>>
}

export interface PrivateKeyFactory {
  tryRandom(): Promiseable<Result<PrivateKey, CryptoError>>
  tryImport(bytes: Uint8Array): Promiseable<Result<PrivateKey, CryptoError>>
}

export interface SignatureFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<Signature, CryptoError>>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly Signature: SignatureFactory
}