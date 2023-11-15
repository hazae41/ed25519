import { Base64Url } from "@hazae41/base64url"
import { Berith } from "@hazae41/berith"
import { Box, BytesOrCopiable } from "@hazae41/box"
import { Result } from "@hazae41/result"
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

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Berith.Memory)
      return Box.greedy(bytesOrCopiable)
    if (bytesOrCopiable instanceof Uint8Array)
      return Box.new(new Berith.Memory(bytesOrCopiable))
    return Box.new(new Berith.Memory(bytesOrCopiable.bytes))
  }

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

    static async randomOrThrow() {
      return new PrivateKey(Berith.Ed25519SigningKey.random())
    }

    static async tryRandom() {
      return await Result.runAndWrap(async () => {
        return await this.randomOrThrow()
      }).then(r => r.mapErrSync(GenerateError.from))
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Berith.Ed25519SigningKey.from_bytes(memory.inner)

      return new PrivateKey(inner)
    }

    static async tryImport(bytes: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await this.importOrThrow(bytes)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    static async importJwkOrThrow(jwk: PrivateKeyJwk) {
      using slice = Base64Url.get().decodeUnpaddedOrThrow(jwk.d)
      using memory = getMemory(slice)

      const inner = Berith.Ed25519SigningKey.from_bytes(memory.inner)

      return new PrivateKey(inner)
    }

    static async tryImportJwk(jwk: PrivateKeyJwk) {
      return await Result.runAndWrap(async () => {
        return await this.importJwkOrThrow(jwk)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    getPublicKeyOrThrow() {
      return new PublicKey(this.inner.public())
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return this.getPublicKeyOrThrow()
      }).mapErrSync(ConvertError.from)
    }

    async signOrThrow(payload: BytesOrCopiable) {
      using memory = getMemory(payload)

      const inner = this.inner.sign(memory.inner)

      return new Signature(inner)
    }

    async trySign(payload: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await this.signOrThrow(payload)
      }).then(r => r.mapErrSync(SignError.from))
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return await this.exportOrThrow()
      }).then(r => r.mapErrSync(ExportError.from))
    }

    async exportJwkOrThrow() {
      using dm = this.inner.to_bytes()
      const d = Base64Url.get().encodeUnpaddedOrThrow(dm)

      using pub = this.inner.public()
      using xm = pub.to_bytes()
      const x = Base64Url.get().encodeUnpaddedOrThrow(xm)

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
      readonly inner: Berith.Ed25519VerifyingKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.Ed25519VerifyingKey) {
      return new PublicKey(inner)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Berith.Ed25519VerifyingKey.from_bytes(memory.inner)

      return new PublicKey(inner)
    }

    static async tryImport(bytes: BytesOrCopiable) {
      return await Result.runAndWrap(async () => {
        return await this.importOrThrow(bytes)
      }).then(r => r.mapErrSync(ImportError.from))
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      using memory = getMemory(payload)

      return this.inner.verify(memory.inner, signature.inner)
    }

    async tryVerify(payload: BytesOrCopiable, signature: Signature) {
      return await Result.runAndWrap(async () => {
        return await this.verifyOrThrow(payload, signature)
      }).then(r => r.mapErrSync(VerifyError.from))
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return await this.exportOrThrow()
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

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Berith.Ed25519Signature.from_bytes(memory.inner)

      return new Signature(inner)
    }

    static tryImport(bytes: BytesOrCopiable) {
      return Result.runAndWrapSync(() => {
        return this.importOrThrow(bytes)
      }).mapErrSync(ImportError.from)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

    tryExport() {
      return Result.runAndWrapSync(() => {
        return this.exportOrThrow()
      }).mapErrSync(ExportError.from)
    }

  }

  return { PrivateKey, PublicKey, Signature }
}