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

### Safe (WebCrypto)

https://github.com/tQsW/webcrypto-curve25519/blob/master/explainer.md

```typescript
import { Ed25519 } from "@hazae41/ed25519"

Ed25519.set(Ed25519.fromSafe())
```

### Berith (WebAssembly)

```bash
npm i @hazae41/berith
```

```typescript
import { Ed25519 } from "@hazae41/ed25519"

Ed25519.set(await Ed25519.fromSafeOrBerith())
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { Ed25519 } from "@hazae41/ed25519"

Ed25519.set(await Ed25519.fromSafeOrNoble())
```
