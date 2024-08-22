import { Base64Url } from "@hazae41/base64url"
import type { ed25519 } from "@noble/curves/ed25519"
import { BytesOrCopiable, Copied } from "libs/copiable/index.js"
import { Adapter, PrivateKeyJwk } from "./adapter.js"
import { fromNative, isNativeSupported } from "./native.js"

export async function fromNativeOrNoble(noble: typeof ed25519) {
  if (await isNativeSupported())
    return fromNative()
  return fromNoble(noble)
}

export function fromNoble(noble: typeof ed25519) {
  const { utils, getPublicKey, sign, verify } = noble

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static async randomOrThrow() {
      return new PrivateKey(utils.randomPrivateKey())
    }

    static async import(bytes: BytesOrCopiable) {
      return new PrivateKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    static async importJwkOrThrow(jwk: PrivateKeyJwk) {
      using memory = Base64Url.get().getOrThrow().decodeUnpaddedOrThrow(jwk.d)

      return new PrivateKey(memory.bytes.slice())
    }

    getPublicKeyOrThrow() {
      return new PublicKey(getPublicKey(this.bytes))
    }

    async signOrThrow(payload: BytesOrCopiable) {
      return new Signature(sign(getBytes(payload), this.bytes))
    }

    async export() {
      return new Copied(this.bytes)
    }

    async exportOrThrow() {
      return await this.export()
    }

    async exportJwkOrThrow() {
      const publicKey = getPublicKey(this.bytes)

      const d = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(this.bytes)
      const x = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(publicKey)

      return { crv: "Ed25519", kty: "OKP", d, x } satisfies PrivateKeyJwk
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static async import(bytes: BytesOrCopiable) {
      return new PublicKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      return verify(signature.bytes, getBytes(payload), this.bytes)
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

  return { PrivateKey, PublicKey, Signature } satisfies Adapter
}