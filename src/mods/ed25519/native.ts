import { Result } from "@hazae41/result";
import { BytesOrCopiable, Copied } from "libs/copiable/index.js";
import { Adapter, SigningKeyJwk } from "./adapter.js";

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

export class NativeCryptoError extends Error {

  constructor(
    readonly options?: ErrorOptions
  ) {
    super("A native crypto error occured", options)
  }

  static from(cause: unknown) {
    return new NativeCryptoError({ cause })
  }

}

export function fromNative() {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class SigningKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKeyPair) {
      return new SigningKey(key)
    }

    static async randomOrThrow(extractable = true) {
      try {
        return new SigningKey(await crypto.subtle.generateKey({ name: "Ed25519" }, extractable, ["sign", "verify"]) as CryptoKeyPair)
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

    static async importJwkOrThrow(jwk: SigningKeyJwk, extractable = true) {
      try {
        const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, x: undefined }, { name: "Ed25519" }, extractable, ["sign"])
        const publicKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, d: undefined }, { name: "Ed25519" }, extractable, ["verify"])

        return new SigningKey({ privateKey, publicKey })
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

    getVerifyingKey() {
      return new VerifyingKey(this.key.publicKey)
    }

    getVerifyingKeyOrThrow() {
      return this.getVerifyingKey()
    }

    async signOrThrow(payload: BytesOrCopiable) {
      try {
        return new Signature(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this.key.privateKey, getBytes(payload))))
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

    async exportJwkOrThrow() {
      try {
        return await crypto.subtle.exportKey("jwk", this.key.privateKey) as SigningKeyJwk
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

  }

  class VerifyingKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKey) {
      return new VerifyingKey(key)
    }

    static async importOrThrow(bytes: BytesOrCopiable, extractable = true) {
      try {
        return new VerifyingKey(await crypto.subtle.importKey("raw", getBytes(bytes), { name: "Ed25519" }, extractable, ["verify"]))
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      try {
        return await crypto.subtle.verify({ name: "Ed25519" }, this.key, signature.bytes, getBytes(payload))
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
    }

    async exportOrThrow() {
      try {
        return new Copied(new Uint8Array(await crypto.subtle.exportKey("raw", this.key)))
      } catch (e: unknown) {
        throw NativeCryptoError.from(e)
      }
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