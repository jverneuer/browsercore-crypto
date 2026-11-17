/**
 * The cryptographic provider contract — canonical definition re-exported.
 *
 * `CryptoProvider` lives in `@browsercore/contracts` (>= 0.2.5) as the single
 * canonical definition (replaceability audit 2026-11-16 found it declared
 * twice — once there with a plain `HashId` union, once here with branded
 * hash ids — bridged only by a cast in fetch). This module re-exports the
 * canonical type so `@browsercore/crypto`'s public surface IS the contracts
 * type: an object implementing one is accepted wherever the other is
 * expected, with no casts.
 *
 * What deliberately stays in THIS package (see `types.ts`): the branded
 * specializations — `HashId` (`Sha256Id | Sha384Id`), the `SHA_256`/`SHA_384`
 * constants, `SymmetricCipherId`, and the per-primitive key-pair interfaces.
 * Branded values remain assignable to the canonical plain-union parameters
 * (verified by compile check), so consumers passing `SHA_256` to
 * `provider.hkdf(...)` compile unchanged.
 *
 * The Node-backed implementation (NodeCryptoProvider) lives in
 * `browsersmith/src/platform/crypto/node/` — this package exports only the
 * contract, types, errors, utilities, and the pure @noble backends. The
 * provider surface is synchronous by design; an async-only backend such as
 * WebCrypto cannot implement it. The canonical rationale lives in
 * @browsercore/contracts >= 0.2.6 (docs/design-decisions.md).
 *
 * @module
 * @since 0.1.0
 */

export type { CryptoProvider } from "@browsercore/contracts";
