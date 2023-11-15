import { BytesOrCopiable, Copiable } from "@hazae41/box"
import { Nullable } from "@hazae41/option"
import { Result } from "@hazae41/result"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"

let global: Nullable<Adapter> = undefined

export function get() {
  if (global == null)
    throw new Error("No Ed25519 adapter found")
  return global
}

export function set(value?: Nullable<Adapter>) {
  global = value
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
  exportOrThrow(): Copiable
  tryExport(): Result<Copiable, ExportError>
}

export interface PublicKey extends Disposable {
  verifyOrThrow(payload: BytesOrCopiable, signature: Signature): Promise<boolean>
  tryVerify(payload: BytesOrCopiable, signature: Signature): Promise<Result<boolean, VerifyError>>

  exportOrThrow(): Promise<Copiable>
  tryExport(): Promise<Result<Copiable, ExportError>>
}

export interface PrivateKey extends Disposable {
  getPublicKeyOrThrow(): PublicKey
  tryGetPublicKey(): Result<PublicKey, ConvertError>

  signOrThrow(payload: BytesOrCopiable): Promise<Signature>
  trySign(payload: BytesOrCopiable): Promise<Result<Signature, SignError>>

  exportJwkOrThrow(): Promise<PrivateKeyJwk>
  tryExportJwk(): Promise<Result<PrivateKeyJwk, ExportError>>
}

export interface PublicKeyFactory {
  importOrThrow(bytes: BytesOrCopiable, extractable?: boolean): Promise<PublicKey>
  tryImport(bytes: BytesOrCopiable, extractable?: boolean): Promise<Result<PublicKey, ImportError>>
}

export interface PrivateKeyFactory {
  randomOrThrow(extractable?: boolean): Promise<PrivateKey>
  tryRandom(extractable?: boolean): Promise<Result<PrivateKey, GenerateError>>

  importJwkOrThrow(jwk: PrivateKeyJwk, extractable?: boolean): Promise<PrivateKey>
  tryImportJwk(jwk: PrivateKeyJwk, extractable?: boolean): Promise<Result<PrivateKey, ImportError>>
}

export interface SignatureFactory {
  importOrThrow(bytes: BytesOrCopiable): Signature
  tryImport(bytes: BytesOrCopiable): Result<Signature, ImportError>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly Signature: SignatureFactory
}