import { Ok } from "@hazae41/result";
import { tryCrypto } from "libs/crypto/crypto.js";
import { Adapter, Copied } from "./ed25519.js";

export async function isSafeSupported() {
  return await tryCrypto(() => crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])).then(r => r.isOk())
}

export function fromSafe(): Adapter {

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static from(key: CryptoKey | CryptoKeyPair) {
      return new PrivateKey(key as CryptoKeyPair)
    }

    static async tryRandom() {
      return await tryCrypto(() => crypto.subtle.generateKey("Ed25519", true, ["verify"])).then(r => r.mapSync(PrivateKey.from))
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "Ed25519", true, ["verify"])).then(r => r.mapSync(PrivateKey.from))
    }

    tryPublic() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async tryExport() {
      return await tryCrypto(() => crypto.subtle.exportKey("raw", this.key.privateKey)).then(r => r.mapSync(x => new Copied(new Uint8Array(x))))
    }

  }

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "Ed25519", true, ["verify"])).then(r => r.mapSync(PublicKey.new))
    }

    async tryVerify(payload: Uint8Array, signature: Signature) {
      return await tryCrypto(() => crypto.subtle.verify("Ed25519", this.key, signature.bytes, payload))
    }

    async tryExport() {
      return await tryCrypto(() => crypto.subtle.exportKey("raw", this.key)).then(r => r.mapSync(x => new Copied(new Uint8Array(x))))
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