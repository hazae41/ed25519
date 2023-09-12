import { Ok, Result } from "@hazae41/result"
import { ed25519 } from "@noble/curves/ed25519"
import { Adapter, Copied } from "./adapter.js"
import { ConvertError, GenerateError, SignError, VerifyError } from "./errors.js"
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