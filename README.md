# Ed25519

Ed25519 for the web

```bash
npm install @hazae41/ed25519
```

[**NPM 📦**](https://www.npmjs.com/package/@hazae41/ed25519)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies

### Why not use WebCrypto
- Safari produces non-deterministic signatures
- Tor browser (Firefox ESR) can't recover public key from private key

## Usage 

```tsx
const key = ed25519.SecretKey.random()
const pub = key.publish()

const msg = Uint8Array.fromHex("deadbeef")
const sig = key.sign(msg)

console.log(pub.verify(msg, sig)) // true
```