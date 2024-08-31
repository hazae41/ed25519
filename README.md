# Ed25519

Ed25519 adapter for WebAssembly and JS implementations

```bash
npm i @hazae41/ed25519
```

[**Node Package 📦**](https://www.npmjs.com/package/@hazae41/ed25519)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies

## Usage

### Native (WebCrypto)

https://github.com/tQsW/webcrypto-curve25519/blob/master/explainer.md

```typescript
import { Ed25519 } from "@hazae41/ed25519"

Ed25519.set(Ed25519.fromNative())
```

### WebAssembly

```bash
npm i @hazae41/ed25519.wasm
```

```typescript
import { Ed25519 } from "@hazae41/ed25519"
import { Ed25519Wasm } from "@hazae41/ed25519.wasm"

await Ed25519Wasm.initBundled()

Ed25519.set(await Ed25519.fromNativeOrWasm(Ed25519Wasm))
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { Ed25519 } from "@hazae41/ed25519"
import { ed25519 } from "@noble/curves/ed25519"

Ed25519.set(await Ed25519.fromNativeOrNoble(ed25519))
```
