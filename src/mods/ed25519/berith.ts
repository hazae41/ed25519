import type { Berith } from "@hazae41/berith"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter } from "./ed25519.js"

export function fromBerith(berith: typeof Berith): Adapter {

  class Signature {

    constructor(
      readonly inner: Berith.Ed25519Signature
    ) { }

    static new(inner: Berith.Ed25519Signature) {
      return new Signature(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => new berith.Ed25519Signature(bytes)).mapSync(Signature.new)
    }

  }

  class PublicKey {

    constructor(
      readonly inner: Berith.Ed25519PublicKey
    ) { }

    static new(inner: Berith.Ed25519PublicKey) {
      return new PublicKey(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => new berith.Ed25519PublicKey(bytes)).mapSync(PublicKey.new)
    }

    tryVerify(payload: Uint8Array, signature: Signature) {
      return tryCryptoSync(() => this.inner.verify(payload, signature.inner))
    }

  }

  return { PublicKey, Signature }
}