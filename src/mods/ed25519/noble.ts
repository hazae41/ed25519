import { Ok } from "@hazae41/result"
import type { ed25519 } from "@noble/curves/ed25519"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter, Copied } from "./ed25519.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromSafeOrNoble(noble: typeof ed25519) {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble(noble)
}

export function fromNoble(noble: typeof ed25519): Adapter {

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static tryRandom() {
      return tryCryptoSync(() => noble.utils.randomPrivateKey()).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PrivateKey(bytes))
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => noble.getPublicKey(this.bytes)).mapSync(PublicKey.new)
    }

    trySign(payload: Uint8Array) {
      return tryCryptoSync(() => noble.sign(payload, this.bytes)).mapSync(Signature.new)
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PublicKey(bytes))
    }

    tryVerify(payload: Uint8Array, signature: Signature) {
      return tryCryptoSync(() => noble.verify(signature.bytes, payload, this.bytes))
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  class Signature {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new Signature(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new Signature(bytes))
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  return { PrivateKey, PublicKey, Signature }
}