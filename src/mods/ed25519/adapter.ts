import { Cursor, CursorWriteError } from "@hazae41/cursor"
import { None, Option } from "@hazae41/option"
import { Ok, Result } from "@hazae41/result"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface Copiable extends Disposable {
  readonly bytes: Uint8Array

  copyAndDispose(): Uint8Array

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

  copyAndDispose() {
    return this.bytes
  }

  trySize(): Result<number, never> {
    return new Ok(this.bytes.length)
  }

  tryWrite(cursor: Cursor): Result<void, CursorWriteError> {
    return cursor.tryWrite(this.bytes)
  }

}

export interface PrivateKeyJwk {
  readonly crv: "Ed25519"
  readonly kty: "OKP"

  /**
   * Base64 private key
   */
  readonly d: string

  /**
   * Base64 public key
   */
  readonly x: string
}

export interface PublicKeyJwk {
  readonly crv: "Ed25519"
  readonly kty: "OKP"

  /**
   * Base64 public key
   */
  readonly x: string
}

export interface Signature extends Disposable {
  tryExport(): Result<Copiable, ExportError>
}

export interface PublicKey extends Disposable {
  tryVerify(payload: Uint8Array, signature: Signature): Promise<Result<boolean, VerifyError>>
  tryExport(): Promise<Result<Copiable, ExportError>>
}

export interface PrivateKey extends Disposable {
  tryGetPublicKey(): Result<PublicKey, ConvertError>
  trySign(payload: Uint8Array): Promise<Result<Signature, SignError>>
  tryExportJwk(): Promise<Result<PrivateKeyJwk, ExportError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Uint8Array): Promise<Result<PublicKey, ImportError>>
}

export interface PrivateKeyFactory {
  tryRandom(): Promise<Result<PrivateKey, GenerateError>>
  tryImportJwk(jwk: PrivateKeyJwk): Promise<Result<PrivateKey, ImportError>>
}

export interface SignatureFactory {
  tryImport(bytes: Uint8Array): Result<Signature, ImportError>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly Signature: SignatureFactory
}