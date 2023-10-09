import { Box, Copiable } from "@hazae41/box"
import { None, Option } from "@hazae41/option"
import { Result } from "@hazae41/result"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
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
  tryVerify(payload: Box<Copiable>, signature: Signature): Promise<Result<boolean, VerifyError>>
  tryExport(): Promise<Result<Copiable, ExportError>>
}

export interface PrivateKey extends Disposable {
  tryGetPublicKey(): Result<PublicKey, ConvertError>
  trySign(payload: Box<Copiable>): Promise<Result<Signature, SignError>>
  tryExportJwk(): Promise<Result<PrivateKeyJwk, ExportError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Box<Copiable>): Promise<Result<PublicKey, ImportError>>
}

export interface PrivateKeyFactory {
  tryRandom(): Promise<Result<PrivateKey, GenerateError>>
  tryImportJwk(jwk: PrivateKeyJwk): Promise<Result<PrivateKey, ImportError>>
}

export interface SignatureFactory {
  tryImport(bytes: Box<Copiable>): Result<Signature, ImportError>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly Signature: SignatureFactory
}