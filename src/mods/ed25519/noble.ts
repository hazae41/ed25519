import { Base64Url } from "@hazae41/base64url"
import { BytesOrCopiable, Copied } from "@hazae41/box"
import { Ok, Result } from "@hazae41/result"
import { ed25519 } from "@noble/curves/ed25519"
import { Adapter, PrivateKeyJwk } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromSafeOrNoble() {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble()
}

export function fromNoble(): Adapter {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static async randomOrThrow() {
      return new PrivateKey(ed25519.utils.randomPrivateKey())
    }

    static async tryRandom() {
      return await Result.runAndWrap(async () => {
        return await this.randomOrThrow()
      }).then(r => r.mapErrSync(GenerateError.from))
    }

    static async import(bytes: BytesOrCopiable) {
      return new PrivateKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    static async tryImport(bytes: BytesOrCopiable) {
      return new Ok(await this.import(bytes))
    }

    static async importJwkOrThrow(jwk: PrivateKeyJwk) {
      return new PrivateKey(Base64Url.get().decodeUnpaddedOrThrow(jwk.d).copyAndDispose())
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.runAndWrap(async () => {
        return await this.importJwkOrThrow(jwk)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    getPublicKeyOrThrow() {
      return new PublicKey(ed25519.getPublicKey(this.bytes))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return this.getPublicKeyOrThrow()
      }).mapErrSync(ConvertError.from)
    }

    async signOrThrow(payload: BytesOrCopiable) {
      return new Signature(ed25519.sign(getBytes(payload), this.bytes))
    }

    async trySign(payload: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await this.signOrThrow(payload)
      }).then(r => r.mapErrSync(SignError.from))
    }

    async export() {
      return new Copied(this.bytes)
    }

    async exportOrThrow() {
      return await this.export()
    }

    async tryExport() {
      return new Ok(await this.export())
    }

    async exportJwkOrThrow() {
      const publicKey = ed25519.getPublicKey(this.bytes)

      const d = Base64Url.get().encodeUnpaddedOrThrow(this.bytes)
      const x = Base64Url.get().encodeUnpaddedOrThrow(publicKey)

      return { crv: "Ed25519", kty: "OKP", d, x } satisfies PrivateKeyJwk
    }

    async tryExportJwk() {
      return await Result.runAndWrap(async () => {
        return await this.exportJwkOrThrow()
      }).then(r => r.mapErrSync(ExportError.from))
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

    static async import(bytes: BytesOrCopiable) {
      return new PublicKey(getBytes(bytes).slice())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return await this.import(bytes)
    }

    static async tryImport(bytes: BytesOrCopiable) {
      return new Ok(await this.import(bytes))
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      return ed25519.verify(signature.bytes, getBytes(payload), this.bytes)
    }

    async tryVerify(payload: BytesOrCopiable, signature: Signature) {
      return await Result.runAndWrap(async () => {
        return await this.verifyOrThrow(payload, signature)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async export() {
      return new Copied(this.bytes)
    }

    async exportOrThrow() {
      return await this.export()
    }

    async tryExport() {
      return new Ok(await this.export())
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