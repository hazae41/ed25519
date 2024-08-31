import { None, Nullable, Option } from "@hazae41/option"
import { BytesOrCopiable, Copiable } from "libs/copiable/index.js"

let global: Option<Adapter> = new None()

export function get() {
  return global
}

export function set(value: Nullable<Adapter>) {
  global = Option.wrap(value)
}

export interface SigningKeyJwk {
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

export interface VerifyingKeyJwk {
  readonly crv: "Ed25519"
  readonly kty: "OKP"

  /**
   * Base64 public key
   */
  readonly x: string
}

export interface Signature extends Disposable {
  exportOrThrow(): Copiable
}

export interface VerifyingKey extends Disposable {
  verifyOrThrow(payload: BytesOrCopiable, signature: Signature): Promise<boolean>

  exportOrThrow(): Promise<Copiable>
}

export interface SigningKey extends Disposable {
  getVerifyingKeyOrThrow(): VerifyingKey

  signOrThrow(payload: BytesOrCopiable): Promise<Signature>

  exportJwkOrThrow(): Promise<SigningKeyJwk>
}

export interface VerifyingKeyFactory {
  importOrThrow(bytes: BytesOrCopiable, extractable?: boolean): Promise<VerifyingKey>
}

export interface SigningKeyFactory {
  randomOrThrow(extractable?: boolean): Promise<SigningKey>

  importJwkOrThrow(jwk: SigningKeyJwk, extractable?: boolean): Promise<SigningKey>
}

export interface SignatureFactory {
  importOrThrow(bytes: BytesOrCopiable): Signature
}

export interface Adapter {
  readonly SigningKey: SigningKeyFactory
  readonly VerifyingKey: VerifyingKeyFactory
  readonly Signature: SignatureFactory
}