import { BytesOrCopiable, Copied } from "@hazae41/box";
import { Ok, Result } from "@hazae41/result";
import { Adapter, PrivateKeyJwk } from "./adapter.js";
import { ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js";

export async function isSafeSupported() {
  return await Result.runAndWrap(() => {
    return crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
  }).then(r => r.isOk())
}

export async function fromSafeOrNull() {
  if (await isSafeSupported())
    return fromSafe()
  return undefined
}

export function fromSafe(): Adapter {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static async randomOrThrow(extractable = true) {
      return new PrivateKey(await crypto.subtle.generateKey("Ed25519", extractable, ["sign", "verify"]) as CryptoKeyPair)
    }

    static async tryRandom(extractable = true) {
      return await Result.runAndWrap(async () => {
        return await this.randomOrThrow(extractable)
      }).then(r => r.mapErrSync(GenerateError.from))
    }

    static async importJwkOrThrow(jwk: PrivateKeyJwk, extractable = true) {
      const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, x: undefined }, "Ed25519", extractable, ["sign"])
      const publicKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, d: undefined }, "Ed25519", extractable, ["verify"])

      return new PrivateKey({ privateKey, publicKey })
    }

    static async tryImportJwk(jwk: PrivateKeyJwk, extractable = true) {
      return await Result.runAndWrap(async () => {
        return await this.importJwkOrThrow(jwk, extractable)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    getPublicKey() {
      return new PublicKey(this.key.publicKey)
    }

    getPublicKeyOrThrow() {
      return this.getPublicKey()
    }

    tryGetPublicKey() {
      return new Ok(this.getPublicKey())
    }

    async signOrThrow(payload: BytesOrCopiable) {
      return new Signature(new Uint8Array(await crypto.subtle.sign("Ed25519", this.key.privateKey, getBytes(payload))))
    }

    async trySign(payload: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await this.signOrThrow(payload)
      }).then(r => r.mapErrSync(SignError.from))
    }

    async exportJwkOrThrow() {
      return await crypto.subtle.exportKey("jwk", this.key.privateKey) as PrivateKeyJwk
    }

    async tryExportJwk() {
      return await Result.runAndWrap(async () => {
        return await this.exportJwkOrThrow()
      }).then(r => r.mapErrSync(ExportError.from))
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

    static async importOrThrow(bytes: BytesOrCopiable, extractable = true) {
      return new PublicKey(await crypto.subtle.importKey("raw", getBytes(bytes), "Ed25519", extractable, ["verify"]))
    }

    static async tryImport(bytes: BytesOrCopiable, extractable = true) {
      return await Result.runAndWrap(async () => {
        return await this.importOrThrow(bytes, extractable)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      return await crypto.subtle.verify("Ed25519", this.key, signature.bytes, getBytes(payload))
    }

    async tryVerify(payload: BytesOrCopiable, signature: Signature) {
      return await Result.runAndWrap(async () => {
        return await this.verifyOrThrow(payload, signature)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async exportOrThrow() {
      return new Copied(new Uint8Array(await crypto.subtle.exportKey("raw", this.key)))
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return await this.exportOrThrow()
      }).then(r => r.mapErrSync(ExportError.from))
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

    static import(bytes: BytesOrCopiable) {
      return new Signature(getBytes(bytes).slice())
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      return this.import(bytes)
    }

    static tryImport(bytes: BytesOrCopiable) {
      return new Ok(this.import(bytes))
    }

    export() {
      return new Copied(this.bytes)
    }

    exportOrThrow() {
      return this.export()
    }

    tryExport() {
      return new Ok(this.export())
    }

  }

  return { PrivateKey, PublicKey, Signature }
}