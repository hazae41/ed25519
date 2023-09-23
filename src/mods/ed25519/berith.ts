import { Base64Url } from "@hazae41/base64url"
import { Berith } from "@hazae41/berith"
import { Ok, Result } from "@hazae41/result"
import { Adapter, PrivateKeyJwk } from "./adapter.js"
import { ConvertError, ExportError, GenerateError, ImportError, SignError, VerifyError } from "./errors.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromSafeOrBerith() {
  if (await isSafeSupported())
    return fromSafe()
  return await fromBerith()
}

export async function fromBerith(): Promise<Adapter> {
  await Berith.initBundledOnce()

  class PrivateKey {

    constructor(
      readonly inner: Berith.Ed25519SigningKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.Ed25519SigningKey) {
      return new PrivateKey(inner)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return Berith.Ed25519SigningKey.random()
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: Uint8Array) {
      return await Result.runAndWrap(() => {
        return Berith.Ed25519SigningKey.from_bytes(bytes)
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PrivateKey.new))
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.unthrow<Result<Berith.Ed25519SigningKey, unknown>>(async t => {
        using slice = Base64Url.get().tryDecodeUnpadded(jwk.d).throw(t)
        return Result.runAndWrapSync(() => Berith.Ed25519SigningKey.from_bytes(slice.bytes))
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PrivateKey.new))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return this.inner.public()
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async trySign(payload: Uint8Array) {
      return await Result.runAndWrap(() => {
        return this.inner.sign(payload)
      }).then(r => r.mapErrSync(SignError.from).mapSync(Signature.new))
    }

    async tryExport() {
      return await Result.runAndWrap(() => {
        return this.inner.to_bytes()
      }).then(r => r.mapErrSync(ExportError.from))
    }

    async tryExportJwk() {
      return await Result.unthrow<Result<PrivateKeyJwk, unknown>>(async t => {
        using dSlice = Result.runAndWrapSync(() => this.inner.to_bytes()).throw(t)
        const d = Base64Url.get().tryEncodeUnpadded(dSlice.bytes).throw(t)

        using pubRef = Result.runAndWrapSync(() => this.inner.public()).throw(t)
        using xSlice = Result.runAndWrapSync(() => pubRef.to_bytes()).throw(t)
        const x = Base64Url.get().tryEncodeUnpadded(xSlice.bytes).throw(t)

        return new Ok({ crv: "Ed25519", kty: "OKP", d, x } as PrivateKeyJwk)
      }).then(r => r.mapErrSync(ExportError.from))
    }

  }

  class PublicKey {

    constructor(
      readonly inner: Berith.Ed25519VerifyingKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.Ed25519VerifyingKey) {
      return new PublicKey(inner)
    }

    static async tryImport(bytes: Uint8Array) {
      return await Result.runAndWrap(() => {
        return Berith.Ed25519VerifyingKey.from_bytes(bytes)
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PublicKey.new))
    }

    async tryVerify(payload: Uint8Array, signature: Signature) {
      return await Result.runAndWrap(() => {
        return this.inner.verify(payload, signature.inner)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async tryExport() {
      return await Result.runAndWrap(() => {
        return this.inner.to_bytes()
      }).then(r => r.mapErrSync(ExportError.from))
    }

  }

  class Signature {

    constructor(
      readonly inner: Berith.Ed25519Signature
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.Ed25519Signature) {
      return new Signature(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return Result.runAndWrapSync(() => {
        return Berith.Ed25519Signature.from_bytes(bytes)
      }).mapErrSync(ImportError.from).mapSync(Signature.new)
    }

    tryExport() {
      return Result.runAndWrapSync(() => {
        return this.inner.to_bytes()
      }).mapErrSync(ExportError.from)
    }

  }

  return { PrivateKey, PublicKey, Signature }
}