import { Base64Url } from "@hazae41/base64url"
import { Box } from "@hazae41/box"
import type { Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Wasm } from "@hazae41/ed25519.wasm"
import { BytesOrCopiable } from "libs/copiable/index.js"
import { Adapter, SigningKeyJwk } from "./adapter.js"
import { fromNative, isNativeSupported } from "./native.js"

export async function fromNativeOrWasm(wasm: typeof Ed25519Wasm) {
  const native = await isNativeSupported()

  if (!native)
    return fromWasm(wasm)

  return fromNative()
}

export function fromWasm(wasm: typeof Ed25519Wasm) {
  const { Memory, Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Signature } = wasm

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Memory)
      return Box.createAsMoved(bytesOrCopiable)
    if (bytesOrCopiable instanceof Uint8Array)
      return Box.create(new Memory(bytesOrCopiable))
    return Box.create(new Memory(bytesOrCopiable.bytes))
  }

  class SigningKey {

    constructor(
      readonly inner: Ed25519SigningKey
    ) { }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Ed25519SigningKey) {
      return new SigningKey(inner)
    }

    static async randomOrThrow() {
      return new SigningKey(Ed25519SigningKey.random())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Ed25519SigningKey.from_bytes(memory.inner)

      return new SigningKey(inner)
    }

    static async importJwkOrThrow(jwk: SigningKeyJwk) {
      using memory = Base64Url.get().getOrThrow().decodeUnpaddedOrThrow(jwk.d)

      using memory2 = getMemory(memory)

      const inner = Ed25519SigningKey.from_bytes(memory2.inner)

      return new SigningKey(inner)
    }

    getVerifyingKeyOrThrow() {
      return new VerifyingKey(this.inner.verifying_key())
    }

    async signOrThrow(payload: BytesOrCopiable) {
      using memory = getMemory(payload)

      const inner = this.inner.sign(memory.inner)

      return new Signature(inner)
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

    async exportJwkOrThrow() {
      using dm = this.inner.to_bytes()

      const d = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(dm)

      using pub = this.inner.verifying_key()

      using xm = pub.to_bytes()

      const x = Base64Url.get().getOrThrow().encodeUnpaddedOrThrow(xm)

      return { crv: "Ed25519", kty: "OKP", d, x } satisfies SigningKeyJwk
    }

  }

  class VerifyingKey {

    constructor(
      readonly inner: Ed25519VerifyingKey
    ) { }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Ed25519VerifyingKey) {
      return new VerifyingKey(inner)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Ed25519VerifyingKey.from_bytes(memory.inner)

      return new VerifyingKey(inner)
    }

    async verifyOrThrow(payload: BytesOrCopiable, signature: Signature) {
      using memory = getMemory(payload)

      return this.inner.verify(memory.inner, signature.inner)
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  class Signature {

    constructor(
      readonly inner: Ed25519Signature
    ) { }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: Ed25519Signature) {
      return new Signature(inner)
    }

    static importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      const inner = Ed25519Signature.from_bytes(memory.inner)

      return new Signature(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  return { SigningKey, VerifyingKey, Signature } satisfies Adapter
}