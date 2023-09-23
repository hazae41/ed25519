import { Base64Url } from "@hazae41/base64url"
import { Ok, Result } from "@hazae41/result"
import { ed25519 } from "@noble/curves/ed25519"
import { Adapter, Copied, PrivateKeyJwk } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromSafeOrNoble() {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble()
}

export function fromNoble(): Adapter {

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return ed25519.utils.randomPrivateKey()
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: Uint8Array) {
      return new Ok(new PrivateKey(bytes))
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.unthrow<Result<PrivateKey, unknown>>(async t => {
        return new Ok(new PrivateKey(Base64Url.get().tryDecodeUnpadded(jwk.d).throw(t).copyAndDispose()))
      }).then(r => r.mapErrSync(ImportError.from))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return ed25519.getPublicKey(this.bytes)
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async trySign(payload: Uint8Array) {
      return await Result.runAndWrap(() => {
        return ed25519.sign(payload, this.bytes)
      }).then(r => r.mapErrSync(SignError.from).mapSync(Signature.new))
    }

    async tryExport() {
      return new Ok(new Copied(this.bytes))
    }

    async tryExportJwk() {
      return await Result.unthrow<Result<PrivateKeyJwk, unknown>>(async t => {
        const d = Base64Url.get().tryEncodeUnpadded(this.bytes).throw(t)

        const publicKey = Result.runAndWrapSync(() => ed25519.getPublicKey(this.bytes)).throw(t)
        const x = Base64Url.get().tryEncodeUnpadded(publicKey).throw(t)

        return new Ok({ crv: "Ed25519", kty: "OKP", d, x } as PrivateKeyJwk)
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

    static async tryImport(bytes: Uint8Array) {
      return new Ok(new PublicKey(bytes))
    }

    async tryVerify(payload: Uint8Array, signature: Signature) {
      return await Result.runAndWrap(() => {
        return ed25519.verify(signature.bytes, payload, this.bytes)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async tryExport() {
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