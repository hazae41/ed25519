import { Ok } from "@hazae41/result"
import type { ed25519 } from "@noble/curves/ed25519"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter } from "./ed25519.js"

export function fromNoble(noble: typeof ed25519): Adapter {

  class Signature {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    static new(bytes: Uint8Array) {
      return new Signature(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new Signature(bytes))
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    static new(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PublicKey(bytes))
    }

    tryVerify(payload: Uint8Array, signature: Signature) {
      return tryCryptoSync(() => noble.verify(signature.bytes, payload, this.bytes))
    }

  }

  return { PublicKey, Signature }
}