import { Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"

export interface Signature { }

export interface PublicKey {
  tryVerify(payload: Uint8Array, signature: Signature): Promiseable<Result<boolean, CryptoError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<PublicKey, CryptoError>>
}

export interface SignatureFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<Signature, CryptoError>>
}

export interface Adapter {
  PublicKey: PublicKeyFactory
  Signature: SignatureFactory
}

