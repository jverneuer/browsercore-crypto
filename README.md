# @browsercore/crypto


[![npm version](https://img.shields.io/npm/v/@browsercore/crypto)](https://www.npmjs.com/package/@browsercore/crypto)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jverneuer/browsercore-crypto/main/.github/coverage-badge.json)](https://github.com/jverneuer/browsercore-crypto/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-crypto/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-crypto/actions/workflows/ci.yml)

Cryptographic primitives for the browsercore stack: secure randomness, hashing
(SHA-256/384), HKDF (RFC 5869), AEAD (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305),
X25519 key exchange, and signature verification. Higher layers — especially TLS —
compose exclusively through the `CryptoProvider` interface, so the backend is
replaceable (WebCrypto, HSM, test double) and never calls `node:crypto` directly.

## Install

```bash
npm install @browsercore/crypto
```

## Quick usage

```ts
import { crypto, NodeCryptoProvider } from "@browsercore/crypto";

// Default singleton, backed by node:crypto:
const key = crypto.randomBytes(32);
const digest = crypto.sha256(key);
const ok = crypto.verifySignature("ecdsa_secp256r1_sha256", pubkey, sig, message);

// Or inject a custom provider (e.g. for tests):
const provider = new NodeCryptoProvider();
const shared = provider.x25519SharedSecret(mySecret, theirPublic);
```

## Public API

| Export | Kind | Purpose |
| --- | --- | --- |
| `crypto` | singleton | Default `CryptoProvider` backend |
| `CryptoProvider` | interface | Pure crypto primitive abstraction higher layers depend on |
| `NodeCryptoProvider` | class | `node:crypto`-backed implementation |
| `aes128Gcm` / `aes256Gcm` / `chacha20Poly1305` | `AeadCipher` | Concrete AEAD descriptors (sizes + encrypt/decrypt) |
| `CIPHER_BY_ID` | record | Every `SymmetricCipherId` mapped to its `AeadCipher` |
| `ensureCryptoError()` | function | Narrow a caught error to a typed crypto error, or wrap it |
| `createCryptoSessionId()` | function | Branded session-id generator |
| `AeadCipher` | interface | Static AEAD parameters + encrypt/decrypt |
| `SymmetricCipherId` | union | `AES-128-GCM \| AES-256-GCM \| ChaCha20-Poly1305` |
| `HashId` | union | `SHA-256 \| SHA-384` |
| `KeyExchangeId` | union | `X25519` |
| `CryptoSessionId` | branded type | Derived-session identifier |
| `X25519KeyPair` | interface | X25519 public + secret key |
| `CryptoError` | class | Base typed error (carries `algorithm` + `cause`) |
| `UnsupportedAlgorithmError` | class | Requested algorithm not supported |
| `DecryptError` | class | AEAD authentication failure |

## Development

This package follows the shared `@browsercore/dev` config used across the
`@browsercore/*` family. That package is the single source of truth for the
TypeScript strict flags, the vitest setup, and the oxlint rules; this repo
extends it instead of keeping its own copies.

| Concern | Mechanism |
| --- | --- |
| TypeScript | `tsconfig.json` `extends @browsercore/dev/tsconfig.base.json` |
| Vitest | `definePackageConfig({ name: "crypto" })` from `@browsercore/dev/vitest` |
| oxlint | `oxlint.config.ts` imports the base object from `@browsercore/dev/oxlint` |
| Coverage report | `coverage-md` bin (from `@browsercore/dev`) replaces the old per-repo script |

Because oxlint's JSON `extends` cannot resolve `node_modules` paths, the lint
config lives in `oxlint.config.ts` rather than `.oxlintrc.json`.

```bash
npm install        # pulls in @browsercore/dev (file:../dev locally)
npm run typecheck  # tsc --noEmit
npm run lint       # oxlint --type-aware src/
npm test           # vitest run
npm run build      # tsc -p tsconfig.build.json (emit to dist/)
```

Generate the coverage report with the shared `coverage-md` binary (writes
`COVERAGE.md` and `coverage/badge.json`, the latter backing the coverage badge
above):

```bash
npx vitest run --coverage
npx coverage-md
```

## License

MIT
