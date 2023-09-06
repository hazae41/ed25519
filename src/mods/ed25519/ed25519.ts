import { Cursor, CursorWriteError } from "@hazae41/cursor"
import { None, Option } from "@hazae41/option"
import { Ok, Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface Copiable extends Disposable {
  readonly bytes: Uint8Array

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

  static new(bytes: Uint8Array) {
    return new Copied(bytes)
  }

  static from(buffer: ArrayBuffer) {
    return new Copied(new Uint8Array(buffer))
  }

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
  tryGetPublicKey(): Promiseable<Result<PublicKey, CryptoError>>
  trySign(payload: Uint8Array): Promiseable<Result<Signature, CryptoError>>
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