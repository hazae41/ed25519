import { Ok, Result } from "@hazae41/result";
import { Adapter, Copied } from "./adapter.js";
import { ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js";

export async function isSafeSupported() {
  return await Result.runAndWrap(() => {
    return crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
  }).then(r => r.isOk())
}

export namespace Pkcs8 {

  /**
   * DER header
   */
  const header = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32])

  export function fromRaw(raw: Uint8Array) {
    const pkcs8 = new Uint8Array(header.length + raw.length)
    pkcs8.set(header, 0)
    pkcs8.set(raw, header.length)
    return pkcs8
  }

  export function intoRaw(pkcs8: Uint8Array) {
    return pkcs8.subarray(header.length)
  }

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
      return await Result.runAndWrap(() => {
        return crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.from))
    }

    static async tryImport(bytes: Uint8Array) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.importKey("pkcs8", Pkcs8.fromRaw(bytes), "Ed25519", true, ["sign", "verify"])
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PrivateKey.from))
    }

    tryGetPublicKey() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async trySign(payload: Uint8Array) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.sign("Ed25519", this.key.privateKey, payload)
      }).then(r => r.mapErrSync(SignError.from).mapSync(Signature.from))
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return Pkcs8.intoRaw(new Uint8Array(await crypto.subtle.exportKey("pkcs8", this.key.privateKey)))
      }).then(r => r.mapErrSync(ExportError.from).mapSync(Copied.from))
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
      return await Result.runAndWrap(() => {
        return crypto.subtle.importKey("raw", bytes, "Ed25519", true, ["verify"])
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PublicKey.new))
    }

    async tryVerify(payload: Uint8Array, signature: Signature) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.verify("Ed25519", this.key, signature.bytes, payload)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async tryExport() {
      return await Result.runAndWrap(() => {
        return crypto.subtle.exportKey("raw", this.key)
      }).then(r => r.mapErrSync(ExportError.from).mapSync(Copied.from))
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

    static from(buffer: ArrayBuffer) {
      return new Signature(new Uint8Array(buffer))
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