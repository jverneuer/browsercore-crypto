# @browsercore/crypto


[![npm version](https://img.shields.io/npm/v/@browsercore/crypto)](https://www.npmjs.com/package/@browsercore/crypto)
[![coverage](https://img.shields.io/endpoint?url=https://jverneuer.github.io/browsercore-crypto/badge.json)](https://jverneuer.github.io/browsercore-crypto/COVERAGE.md)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-crypto/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@browsercore/crypto.svg)](LICENSE)

The synchronous `CryptoProvider` contract, branded algorithm identifiers, typed
errors, and pure-JavaScript key-exchange backends for the browsercore stack:
X25519 and NIST-curve ECDH (`@noble/curves`) plus ML-KEM-768
(`@noble/post-quantum`), covering the TLS 1.3 hybrid `X25519MLKEM768` group with
zero `node:*` imports. Higher layers (TLS, mostly) compose exclusively
through the `CryptoProvider` interface, never `node:crypto` directly.

**The interface is synchronous by design.** Any *synchronous* backend can
implement it: the pure-JS noble backends exported here, a `node:crypto` adapter,
a blocking HSM client, or a wasm build with sync exports. Async-native APIs,
WebCrypto (`SubtleCrypto`) above all, **cannot** implement it: a Promise-based
API cannot be served from a sync method signature. The canonical rationale lives
in the design-decisions note shipped with
[`@browsercore/contracts` ≥ 0.2.6](https://github.com/jverneuer/browsercore-contracts/blob/main/docs/design-decisions.md).

The concrete `node:crypto`-backed provider (randomness, hashing, HKDF, AEAD,
signature verification) is wired in the
[browsersmith](https://github.com/jverneuer/browsersmith) adapter
(`src/platform/crypto/node/`); this package exports the contract, branded
types, errors, DER helpers, and the noble backends.

## Install

```bash
npm install @browsercore/crypto
```

## Quick usage

```ts
import {
    NobleX25519Backend,
    NobleMlKem768Backend,
    type CryptoProvider,
} from "@browsercore/crypto";

// Pure-JS key exchange, sync by design, zero node:* imports:
const x25519 = new NobleX25519Backend();
const publicKey = x25519.publicKey(mySecretScalar);
const sharedSecret = x25519.sharedSecret(mySecretScalar, peerPublicKey);

const mlkem = new NobleMlKem768Backend();
const { ciphertext, sharedSecret: pqSecret } = mlkem.encapsulate(peerMlKemKey);

// Higher layers depend on the sync contract only. Implement it with any
// SYNC backend (e.g. browsersmith's node:crypto-backed provider, a test
// double, a blocking HSM client), never an async-native one like WebCrypto:
const provider: CryptoProvider = mySyncProvider;
```

## Public API

| Export | Kind | Purpose |
| --- | --- | --- |
| `CryptoProvider` | interface | Synchronous crypto-primitive abstraction (canonical type re-exported from `@browsercore/contracts`); async-native backends such as WebCrypto cannot implement it |
| `NobleX25519Backend` | class | Pure-JS X25519 backend (`@noble/curves`) |
| `NobleEcdhBackend` | class | Pure-JS NIST-curve ECDH backend, secp256r1/secp384r1 (`@noble/curves`) |
| `NobleMlKem768Backend` | class | Pure-JS ML-KEM-768 backend, FIPS 203 (`@noble/post-quantum`) |
| `X25519Backend` / `EcdhBackend` / `MlKem768Backend` | interfaces | Sync backend contracts the noble classes implement |
| `rawPrivateToPkcs8` / `pkcs8ToRaw` / `rawPublicToSpki` / `spkiToRaw` | functions | X25519 DER container conversions (RFC 8410) |
| `AES_128_GCM` / `AES_256_GCM` / `AES_128_CCM` / `CHACHA20_POLY1305` / `SHA_256` / `SHA_384` / `X25519` | constants | Branded canonical algorithm identifiers |
| `ensureCryptoError()` | function | Narrow a caught error to a typed crypto error, or wrap it |
| `createCryptoSessionId()` | function | Branded session-id generator |
| `AeadCipher` | interface | Static AEAD parameters + encrypt/decrypt |
| `SymmetricCipherId` | union | `AES-128-GCM \| AES-256-GCM \| AES-128-CCM \| ChaCha20-Poly1305` |
| `HashId` | union | `SHA-256 \| SHA-384` |
| `KeyExchangeId` | union | `X25519` |
| `EcdhCurve` / `EcdhKeyPair` | union / interface | Named-curve ECDH identifiers and wire-layout key pair |
| `MLKEM768KeyPair` / `MLKEM768Encapsulation` | interfaces | FIPS 203 key pair and encapsulation result |
| `MLKEM768_*_LENGTH` | constants | FIPS 203 parameter-set byte sizes |
| `CryptoSessionId` | branded type | Derived-session identifier |
| `X25519KeyPair` | interface | X25519 public + secret key |
| `CryptoError` | class | Base typed error (carries `algorithm` + `cause`) |
| `UnsupportedAlgorithmError` | class | Requested algorithm not supported |
| `DecryptError` | class | AEAD authentication failure |
| `assertNever` / `createId` | functions | Shared exhaustiveness / id helpers |

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


## Contributing

Contributions are welcome: bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-crypto/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
