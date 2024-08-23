import { Result } from "@hazae41/result";
import { BytesOrCopiable, Copied } from "libs/copiable/index.js";
import { Adapter, PrivateKeyJwk } from "./adapter.js";

export async function isNativeSupported() {
  return await Result.runAndWrap(async () => {
    return await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
  }).then(r => r.isOk())
}

export async function fromNativeOrNull() {
  const native = await isNativeSupported()

  if (!native)
    return

  return fromNative()
}

export function fromNative() {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static async randomOrThrow(extractable = true) {
      return new PrivateKey(await crypto.subtle.generateKey("Ed25519", extractable, ["sign", "verify"]))
    }

    static async importJwkOrThrow(jwk: PrivateKeyJwk, extractable = true) {
      const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, x: undefined }, "Ed25519", extractable, ["sign"])
      const publicKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, d: undefined }, "Ed25519", extractable, ["verify"])

      return new PrivateKey({ privateKey, publicKey })
    }

    getPublicKey() {
      return new PublicKey(this.key.publicKey)
    }

    getPublicKeyOrThrow() {
      return this.getPublicKey()
    }

    async signOrThrow(payload: BytesOrCopiable) {
      return new Signature(new Uint8Array(await crypto.subtle.sign("Ed25519", this.key.privateKey, getBytes(payload))))
    }

    async exportJwkOrThrow() {
      return await crypto.subtle.exportKey("jwk", this.key.privateKey) as PrivateKeyJwk
    }

  }

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async importOrThrow(bytes: BytesOrCopiable, extractable = true) {
      return new PublicKey(await crypto.subtle.importKey("raw", getBytes(bytes), "Ed25519", extractable, ["verify"]))
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      return await crypto.subtle.verify("Ed25519", this.key, signature.bytes, getBytes(payload))
    }

    async exportOrThrow() {
      return new Copied(new Uint8Array(await crypto.subtle.exportKey("raw", this.key)))
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