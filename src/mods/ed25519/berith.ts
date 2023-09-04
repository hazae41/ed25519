import type { Berith } from "@hazae41/berith"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { Adapter } from "./ed25519.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromNativeOrBerith(berith: typeof Berith) {
  if (await isSafeSupported())
    return fromSafe()
  await berith.initBundledOnce()
  return fromBerith(berith)
}

export function fromBerith(berith: typeof Berith): Adapter {

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

    static tryRandom() {
      return tryCryptoSync(() => berith.Ed25519SigningKey.random()).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => berith.Ed25519SigningKey.from_bytes(bytes)).mapSync(PrivateKey.new)
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => this.inner.public()).mapSync(PublicKey.new)
    }

    trySign(payload: Uint8Array) {
      return tryCryptoSync(() => this.inner.sign(payload)).mapSync(Signature.new)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
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

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => berith.Ed25519VerifyingKey.from_bytes(bytes)).mapSync(PublicKey.new)
    }

    tryVerify(payload: Uint8Array, signature: Signature) {
      return tryCryptoSync(() => this.inner.verify(payload, signature.inner))
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
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
      return tryCryptoSync(() => berith.Ed25519Signature.from_bytes(bytes)).mapSync(Signature.new)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  return { PrivateKey, PublicKey, Signature }
}