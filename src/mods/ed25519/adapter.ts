import { None, Nullable, Option } from "@hazae41/option"
import { BytesOrCopiable, Copiable } from "libs/copiable/index.js"

let global: Option<Adapter> = new None()

export function get() {
  return global
}

export function set(value: Nullable<Adapter>) {
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
  exportOrThrow(): Copiable
}

export interface PublicKey extends Disposable {
  verifyOrThrow(payload: BytesOrCopiable, signature: Signature): Promise<boolean>

  exportOrThrow(): Promise<Copiable>
}

export interface PrivateKey extends Disposable {
  getPublicKeyOrThrow(): PublicKey

  signOrThrow(payload: BytesOrCopiable): Promise<Signature>

  exportJwkOrThrow(): Promise<PrivateKeyJwk>
}

export interface PublicKeyFactory {
  importOrThrow(bytes: BytesOrCopiable, extractable?: boolean): Promise<PublicKey>
}

export interface PrivateKeyFactory {
  randomOrThrow(extractable?: boolean): Promise<PrivateKey>

  importJwkOrThrow(jwk: PrivateKeyJwk, extractable?: boolean): Promise<PrivateKey>
}

export interface SignatureFactory {
  importOrThrow(bytes: BytesOrCopiable): Signature
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
  readonly Signature: SignatureFactory
}