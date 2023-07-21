import { Ok } from "@hazae41/result";
import { tryCrypto } from "libs/crypto/crypto.js";
import { Adapter } from "./ed25519.js";

export async function isSafeSupported() {
  return await tryCrypto(() => crypto.subtle.generateKey("Ed25519", false, [])).then(r => r.isOk())
}

export function fromSafe(): Adapter {

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
      readonly key: CryptoKey
    ) { }

    static new(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "Ed25519", false, ["verify"])).then(r => r.mapSync(PublicKey.new))
    }

    async tryVerify(payload: Uint8Array, signature: Signature) {
      return await tryCrypto(() => crypto.subtle.verify("Ed25519", this.key, signature.bytes, payload))
    }

  }

  return { PublicKey, Signature }
}