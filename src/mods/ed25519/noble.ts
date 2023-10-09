import { Base64Url } from "@hazae41/base64url"
import { Box, Copiable, Copied } from "@hazae41/box"
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

  class PrivateKey {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new PrivateKey(bytes)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return new Box(new Copied(ed25519.utils.randomPrivateKey()))
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: Box<Copiable>) {
      return new Ok(new PrivateKey(bytes))
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.unthrow<Result<PrivateKey, unknown>>(async t => {
        return new Ok(new PrivateKey(new Box(Base64Url.get().tryDecodeUnpadded(jwk.d).throw(t))))
      }).then(r => r.mapErrSync(ImportError.from))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return new Box(new Copied(ed25519.getPublicKey(this.bytes.get().bytes)))
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async trySign(payload: Box<Copiable>) {
      return await Result.runAndWrap(() => {
        return new Box(new Copied(ed25519.sign(payload.get().bytes, this.bytes.get().bytes)))
      }).then(r => r.mapErrSync(SignError.from).mapSync(Signature.new))
    }

    async tryExport() {
      return new Ok(this.bytes.unwrap())
    }

    async tryExportJwk() {
      return await Result.unthrow<Result<PrivateKeyJwk, unknown>>(async t => {
        const d = Base64Url.get().tryEncodeUnpadded(this.bytes).throw(t)

        const publicKey = Result.runAndWrapSync(() => ed25519.getPublicKey(this.bytes.get().bytes)).throw(t)
        const x = Base64Url.get().tryEncodeUnpadded(new Box(new Copied(publicKey))).throw(t)

        return new Ok({ crv: "Ed25519", kty: "OKP", d, x } as PrivateKeyJwk)
      }).then(r => r.mapErrSync(ExportError.from))
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new PublicKey(bytes)
    }

    static async tryImport(bytes: Box<Copiable>) {
      return new Ok(new PublicKey(bytes))
    }

    async tryVerify(payload: Box<Copiable>, signature: Signature) {
      return await Result.runAndWrap(() => {
        return ed25519.verify(signature.bytes.get().bytes, payload.get().bytes, this.bytes.get().bytes)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  class Signature {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]
    }

    static new(bytes: Box<Copiable>) {
      return new Signature(bytes)
    }

    static tryImport(bytes: Box<Copiable>) {
      return new Ok(new Signature(bytes))
    }

    tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  return { PrivateKey, PublicKey, Signature }
}