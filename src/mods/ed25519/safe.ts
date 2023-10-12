import { BytesOrCopiable, Copied } from "@hazae41/box";
import { Ok, Result } from "@hazae41/result";
import { Adapter, PrivateKeyJwk } from "./adapter.js";
import { ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js";

export async function isSafeSupported() {
  return await Result.runAndWrap(() => {
    return crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
  }).then(r => r.isOk())
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

    static from(key: CryptoKey | CryptoKeyPair) {
      return new PrivateKey(key as CryptoKeyPair)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.from))
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.runAndWrap(async () => {
        const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, x: undefined }, "Ed25519", true, ["sign"])
        const publicKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: undefined, d: undefined }, "Ed25519", true, ["verify"])
        return new PrivateKey({ privateKey, publicKey })
      }).then(r => r.mapErrSync(ImportError.from))
    }

    tryGetPublicKey() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async trySign(payload: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await crypto.subtle.sign("Ed25519", this.key.privateKey, getBytes(payload))
      }).then(r => r.mapErrSync(SignError.from).mapSync(Signature.create))
    }

    async tryExportJwk(): Promise<Result<PrivateKeyJwk, ExportError>> {
      return await Result.runAndWrap(async () => {
        return await crypto.subtle.exportKey("jwk", this.key.privateKey) as PrivateKeyJwk
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

    static async tryImport(bytes: BytesOrCopiable) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.importKey("raw", getBytes(bytes), "Ed25519", true, ["verify"])
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PublicKey.new))
    }

    async tryVerify(payload: BytesOrCopiable, signature: Signature) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.verify("Ed25519", this.key, signature.bytes, getBytes(payload))
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return new Uint8Array(await crypto.subtle.exportKey("raw", this.key))
      }).then(r => r.mapErrSync(ExportError.from).mapSync(Copied.new))
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

    static create(buffer: ArrayBuffer) {
      return new Signature(new Uint8Array(buffer))
    }

    static tryImport(bytes: BytesOrCopiable) {
      return new Ok(new Signature(getBytes(bytes).slice()))
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  return { PrivateKey, PublicKey, Signature }
}