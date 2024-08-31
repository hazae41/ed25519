import { Base64Url } from "@hazae41/base64url"
import type * as Ed25519CurvesNoble from "@noble/curves/ed25519"
import type * as Ed25519DirectNoble from "@noble/ed25519"
import { BytesOrCopiable, Copied } from "libs/copiable/index.js"
import { Adapter, SigningKeyJwk } from "./adapter.js"
import { fromNative, isNativeSupported } from "./native.js"

export type Ed25519Curve =
  | typeof Ed25519CurvesNoble.ed25519
  | typeof Ed25519DirectNoble

export interface Ed25519Noble {
  readonly ed25519: Ed25519Curve
}

export async function fromNativeOrNoble(noble: Ed25519Noble) {
  const native = await isNativeSupported()

  if (!native)
    return fromNoble(noble)

  return fromNative()
}

export function fromNoble(noble: Ed25519Noble) {
  const { ed25519 } = noble

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class SigningKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new SigningKey(bytes)
    }

    static async randomOrThrow() {
      return new SigningKey(ed25519.utils.randomPrivateKey())
    }

    static async import(bytes: BytesOrCopiable) {
      return new SigningKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    static async importJwkOrThrow(jwk: SigningKeyJwk) {
      using memory = Base64Url.get().getOrThrow().decodeUnpaddedOrThrow(jwk.d)

      return new SigningKey(memory.bytes.slice())
    }

    getVerifyingKeyOrThrow() {
      return new VerifyingKey(ed25519.getPublicKey(this.bytes))
    }

    async signOrThrow(payload: BytesOrCopiable) {
      return new Signature(ed25519.sign(getBytes(payload), this.bytes))
    }

    async export() {
      return new Copied(this.bytes)
    }

    async exportOrThrow() {
      return await this.export()
    }

    async exportJwkOrThrow() {
      const publicKey = ed25519.getPublicKey(this.bytes)

      const d = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(this.bytes)
      const x = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(publicKey)

      return { crv: "Ed25519", kty: "OKP", d, x } satisfies SigningKeyJwk
    }

  }

  class VerifyingKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new VerifyingKey(bytes)
    }

    static async import(bytes: BytesOrCopiable) {
      return new VerifyingKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      return ed25519.verify(signature.bytes, getBytes(payload), this.bytes)
    }

    async export() {
      return new Copied(this.bytes)
    }

    async exportOrThrow() {
      return await this.export()
    }

  }

  class Signature {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new Signature(bytes)
    }

    static import(bytes: BytesOrCopiable) {
      return new Signature(getBytes(bytes).slice())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      return this.import(bytes)
    }

    export() {
      return new Copied(this.bytes)
    }

    exportOrThrow() {
      return this.export()
    }

  }

  return { SigningKey, VerifyingKey, Signature } satisfies Adapter
}