# Changelog

## 0.9.1 (2026-09-25)

### Changed

- **nacljc 0.3.1:** after every operation that reads a secret (all vault
  operations under the `:sodium` provider), the stack the C code used is
  wiped with `sodium_stackzero`, as libsodium's memory docs recommend.
  About 0.2 µs per operation. No API change.

## 0.9.0 (2026-09-25)

Sessions on vault handles (`docs/08-sessions-on-handles-plan.md`).

### Changed

- **`signet.session` keeps its secrets in the vault.** The chaining key,
  handshake key, transport keys and ephemerals are vault session entries,
  in the vault of the local static key; a state holds only handles and
  public values, so printing it shows nothing secret. Under the `:sodium`
  provider they stay in libsodium's guarded memory.
- **`initiator` / `responder` take a vault handle** as the local static
  key, and the peer as a public key or a kid (`::unknown-peer` if it cannot
  be resolved). Key records still work, deprecated; their session secrets
  go to the `:vault` option's vault (default `:default`).
- Each successful `write-message!` / `read-message!` destroys the secrets
  only the consumed state needed; a failed or racing call destroys what it
  created, so a forged message leaves nothing behind.
- State keys renamed: `:local-static`, `:local-ephemeral`.
- `initiator` / `responder` draw a random session id (documented as
  impure: a read of the random generator).
- nacljc 0.3.0 (`secret-split`, secret HKDF salt).

### Added

- **`session/close!`:** destroys every secret of a session from any of its
  states (even the first); any later use throws `::session-closed`.
- **`session/with-conclave`:** closes the session when the block exits,
  also on an exception. A clj-kondo `lint-as` export ships with the jar.
- **`vault/session-entry-count`:** how many session secrets a vault holds,
  to monitor sessions that were never closed.
- Internal: vault session entries (never on the public side, never in
  `handles`, not exportable: `::not-exportable`), `impl/split-material`.
- The `:sodium` provider moves byte material it adopts into guarded
  memory, so it only ever holds secrets.
- **`ssh/import-keypair!`:** imports an OpenSSH Ed25519 private key file
  into a vault and returns a handle; the seed must give the file's public
  key (`:public-key-mismatch` otherwise).

### Deprecated (decision 17)

Secret-carrying key records are deprecated in favour of vault handles.
Nothing is removed; the functions below carry `^{:deprecated "0.9.0"}`
(clj-kondo warns) and a docstring pointer to the replacement:

- `key/signing-keypair`, `key/signing-keypair!` → `vault/generate-signing-key!`
  / `vault/import-signing-key!` (secp256k1 has no vault equivalent yet)
- `key/encryption-keypair`, `key/encryption-keypair!` →
  `vault/generate-encryption-key!` / `vault/import-encryption-key!`
- `key/signing-private-key`, `key/encryption-private-key`,
  `key/private-key` → a vault handle
- `key/raw-shared-secret` → `signet.shared/shared-key!`
- `ssh/read-private-key`, `ssh/load-keypair`, `ssh/load-keypair!` →
  `ssh/import-keypair!`

Key-record inputs to sign, box, chain and session keep working.
Public-key records and functions are not deprecated.

### Fixed

- **`signet.session` is now wire-compatible with Noise.** The handshake
  mixed the prologue into the transcript hash after the static public
  keys; the Noise spec (§5.3) mixes it first. Handshake messages
  therefore matched no other `Noise_KK_25519_ChaChaPoly_SHA256`
  implementation. **Breaking:** a 0.9.0 peer cannot complete a handshake
  with a 0.8.0 or earlier peer (the first message fails authentication).
  Transport messages were not affected.

### Added

- Known-answer tests against the published Noise_KK vectors of cacophony
  and snow (`test/signet/noise_vectors_test.clj`), on every backend.

## 0.8.0 (2026-09-24)

Secrets by reference: code holds vault handles, never secret bytes
(`docs/07-secret-handles-design.md`, decisions 7–16).

### Added

- **`signet.vault`:**
  - `KeyHandle` records naming a key and its vault; a vault registry with
    `:default`.
  - Two sides indexed by one kid: `lookup` and `register-public-key!`,
    `handle` and `handles`.
  - Keys born in the vault: `generate-signing-key!`,
    `generate-encryption-key!`.
  - `import-signing-key!` and `import-encryption-key!` (they wipe the
    caller's array); `export-secret` (requires
    `{:i-understand :exposes-secret}`); `destroy!`.
  - `sign`, `public-key`, `algorithm`.
  - The default identity: `default-signing-key`,
    `set-default-signing-key!`, `ensure-default-signing-key!` (race-safe).
- **Providers:** `:memory` (heap, inside the vault, lent copies wiped) and
  `:sodium` (`signet.vault.sodium`, on nacljc 0.2.0 secrets in libsodium
  guarded memory; derived secrets stay there). `default-provider` picks
  `:sodium` on the libsodium backend.
- **Handles everywhere:** `sign/sign` and `sign-edn` take handles. `box`
  takes a handle sender; `unbox` takes a handle, a set of handles, or a
  vault id. `chain/extend` takes a handle root.
- **Chains:** an open token's `:proof` is a vault handle;
  `chain/export-token` (sendable form, needs the acknowledgement),
  `chain/import-token!` (refuses a mismatched proof), `chain/discard!`;
  `close` destroys the proof.
- **`signet.shared`:**
  - `shared-key!`: both parties derive the same key and kid with no
    exchange.
  - `seal` and `open`: directional, key-committing, with a per-message salt.
  - `mac` and `verify-mac?`: directional.

### Changed (breaking)

- The default identity is the vault's. Removed:
  `key/set-default-signing-keypair!`, `key/set-default-encryption-keypair!`,
  `key/default-signing-keypair`, `key/default-encryption-keypair`,
  `key/clear-defaults!`, `key/ensure-default-signing-keypair!`.
  `sign/sign-edn!` and key-less `chain/extend` use
  `vault/ensure-default-signing-key!` / `vault/default-signing-key`.
- An open chain token's `:proof` is a handle, not the seed. Use
  `export-token` to send one.
- nacljc 0.2.0.

### Tooling

- `bb check-not-released`, run by `test:jar`, refuses to install a version
  already on Clojars. It prevents a local build shadowing a published jar
  in ~/.m2.

## 0.7.1 (2026-09-23)

Dependency update only; no API or behaviour change.

- cedn 1.6.0 (was 1.5.2). It only renames functions (`cedn/check`,
  `cedn.error/throw-*`, with the old names deprecated), so the canonical
  bytes, and therefore signatures, are unchanged. signet uses none of the
  renamed functions.
- uuidv7 0.7.2 (was 0.7.1). Its generator step is now a pure function; the
  UUID format and distribution are unchanged.

These two should have been released before signet 0.7.0; 0.7.1 catches
up.

## 0.7.0 (2026-09-23)

The first release on Clojars (`com.github.franks42/signet`). Earlier
versions were git tags only. There are breaking changes from 0.6.0; see
"Changed" below and the README's "Compatibility".

### Added

- **libsodium backend** (`signet.impl.sodium`, through
  [nacljc](https://github.com/franks42/nacljc) 0.1.0), selected with
  `-Dsignet.backend=sodium` or `SIGNET_BACKEND=sodium`. It is
  byte-identical to the JCA backend (a parity check runs in CI), and the
  full suite also passes on babashka.
- **box v2** (`signet.encryption`): self-describing EDN boxes with
  directional keys (a box cannot be reflected), a per-message HKDF salt
  (safe random nonces at any volume), optional kid slots and an
  authenticated `:aad` slot. `unbox` never throws on malformed input.
  Design: `docs/06-box-v2-design.md`.
- **Registering twins:** `key/signing-keypair!`, `key/encryption-keypair!`,
  `ssh/load-keypair!`. Also `key/ensure-default-signing-keypair!` and
  `sign/sign-edn!`.
- **Redacted printing:** key records print their kid and
  `:d "<redacted>"`, never secret bytes.
- **CI** on JDK 21 and 25 (JCA), plus the libsodium backend on macOS and
  Linux, all through bb tasks.

### Changed (breaking)

- **Pure by default.** Constructors and conversions (`signing-keypair`,
  `encryption-keypair`, `signing-public-key`, `signing-private-key`,
  `encryption-public-key`, `encryption-private-key`, `public-key`,
  `private-key`, `hex->kid`, `raw-shared-secret`, `ssh/load-keypair`) no
  longer register keys. Only functions ending in `!` write the key store or
  the defaults.
- **Registering never sets a default.** The first-one-wins rule is gone.
  Defaults are set with `set-default-signing-keypair!` or
  `ensure-default-signing-keypair!`.
- `sign/sign-edn` always takes a key. The key-less arity is now
  `sign/sign-edn!`.
- `session/write-message` and `session/read-message` are now
  `write-message!` and `read-message!`, since they consume their state.
- **Session states are single-use.** Reusing one throws
  `::stale-session-state`, so a nonce is never reused and a replayed
  message is refused.
- **Trust vocabulary.** `verify-edn` and `chain/verify` never throw, count
  expiry against `:valid?`, and take `:signer` or `:root` for
  `:verified?`, and `:now` for deterministic expiry. The raw signature
  check is now `:signature-valid?`.
- `key/lookup` and `key/kid` no longer register anything.
- `dh` is for static keys and `edh` for ephemeral ones; mixing them up
  throws.
- Removed `key/as-public-key`, `as-encryption-public-key` and
  `as-encryption-private-key` (added in 0.7.0 snapshots; use the now-pure
  `public-key`, `encryption-public-key`, `encryption-private-key`).
- Dependencies: cedn 1.5.2 (canonical bytes changed for some inputs; see
  the README), uuidv7 0.7.1 (secure randomness on ClojureScript).

### Fixed

- **SSH import is strict.**
  - `read-public-key` and `read-private-key` refuse anything but an
    unencrypted Ed25519 key, with `::bad-ssh-key` and a `:reason`.
  - Before, an `ssh-rsa` line or a passphrase-protected key was parsed
    into a wrong key without error.
  - The OpenSSH check-ints and the public-key copies are now verified.
  - `assert`, which can be compiled out, is replaced by ex-info.
- **Typed errors.**
  - Every error is ex-info with a namespaced `:type`: for example
    `::no-private-key`, `::sealed`, `::no-default-signing-keypair`,
    `::authentication-failed`, `::wrong-message-phase`.
  - A session's decryption failure is the same `::authentication-failed`
    on every backend.
  - A local static key without its private part is refused when the
    session is created.
- **Error data carries no key bytes.** Before, a seed passed by mistake
  could end up in ex-data.
- Ephemeral keys are never registered, and are wiped after use, along
  with every DH output.

### Naming convention

`!` means the call writes state that outlives it. Impure reads are
documented, not banged, and `!` never means "may throw". Docstrings state
`Impure: …`, `Throws …` and `Never throws …`. See CLAUDE.md.
