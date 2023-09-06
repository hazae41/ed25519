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

### Berith (WebAssembly)

```typescript
import { Ed25519 } from "@hazae41/ed25519"
import { Berith } from "@hazae41/berith"

await Berith.initBundledOnce()
const ed25519 = Ed25519.fromBerith(Berith)

/**
 * Set it globally (optional)
 **/
Keccak256.set(keccak256)
```

### Noble (JavaScript)

```typescript
import { Ed25519 } from "@hazae41/ed25519"
import * as noble_ed25519 from "@noble/curves/ed25519"

const ed25519 = Ed25519.fromNoble(noble_ed25519.ed25519)

/**
 * Set it globally (optional)
 **/
Keccak256.set(keccak256)
```
