# Signet — CLJC 25519 Crypto Library

## Project Overview
Portable CLJC library for Ed25519/X25519 elliptic curve cryptography: request signing and encryption with EDN-native message formats.

## Architecture — Two Concerns
- **signet**: Crypto primitives — key management, request signing, encryption (DH + symmetric)
- **stroopwafel**: Capability semantics — bearer tokens, Datalog policy, built on signet

## Key Decisions Made
- **Name**: signet (like a signet ring — personal key for signing/sealing)
- **Crypto backends** (`signet.impl` facade, selected once at load: `-Dsignet.backend` / `SIGNET_BACKEND`, default `jca`):
  - `:jca` — `signet.impl.jvm`, Java JCA. No native dependency. Its seed→public-key path (a `proxy [SecureRandom]` trick) does not work on babashka.
  - `:sodium` — `signet.impl.sodium`, libsodium via `sodium.core` (github.com/franks42/sodium.cljc, used as the local snapshot `com.github.franks42/sodium 0.1.0-SNAPSHOT` from `bb install` there — re-install after changing sodium.cljc; babashka.ffi). Needs libsodium >= 1.0.19, JDK 25+ with `--enable-native-access=ALL-UNNAMED`, bb >= 1.13.220. Runs the full suite on bb too. Byte-identical output to `:jca` (`test/signet/backend_parity.clj`).
  - ClojureScript: not implemented (every `:cljs` branch throws). The browser plan is libsodium.js (see `../sodium.cljc/docs/feasibility.md`).
- **Dependencies**: canonical-edn (cedn) 1.5.2 for deterministic serialization, uuidv7 0.7.1 for request IDs (bumped from 1.2.0 / 0.5.0 in 0.7.0-SNAPSHOT; see README "Compatibility"). Bouncy Castle for secp256k1 only (JVM). sodium.cljc for the `:sodium` backend (alias `:sodium`: local snapshot jar, not published).
- **Key fields**: JWK-inspired — `:x` (public), `:d` (private), `:crv` (:Ed25519/:X25519), `:type` (dispatch tag)
- **kid format**: URN — `urn:signet:pk:<algorithm>:<base64url-public-key>` — self-describing, receiver can extract pk directly
- **Key store**: Auto-registering, kid-based lookup, most-info-wins (keypair > private > public)
- **Default keys**: First-one-wins unless explicitly overridden
- **Records**: Separate records per role — KeyPair, PublicKey, PrivateKey per curve
- **Multimethods**: For extensible key construction — open for SSH, JWK, X.509 formats
- **Namespace prefix**: `signet.*` — `signet.key`, `signet.sign`, `signet.chain`, `signet.box`, `signet.encoding`

## Implemented Namespaces

### signet.key — Key management
- Records: Ed25519KeyPair/PublicKey/PrivateKey, X25519KeyPair/PublicKey/PrivateKey, X25519SharedKey
- `signing-keypair` / `encryption-keypair` — multimethod, extensible (generate, from-bytes, from-map)
- `signing-public-key` / `signing-private-key` — extraction multimethods
- `encryption-public-key` / `encryption-private-key` — extraction + Ed25519→X25519 cross-conversion
- `public-key` / `private-key` — same-curve convenience
- `kid` — URN-based key identifier
- `kid->public-key` — parse URN back to public key record
- `raw-shared-secret` — X25519 DH key agreement (accepts Ed25519 keys, auto-converts)
- Auto-registering key store with `lookup`, `register!`, `unregister!`
- Default signing/encryption keypairs (first-one-wins)
- Predicates: `signing-keypair?`, `signing-public-key?`, etc.

### signet.sign — Request signing
- Low-level: `sign` / `verify` (bytes in, bytes out)
- High-level: `sign-edn` / `verify-edn` (EDN envelopes with cedn + UUIDv7)
- Zero-config: `(sign-edn payload)` uses default keypair, auto-generates if needed
- TTL/expiration support
- Digests: `message-digest` (same across signers), `digest` (unique per envelope)

### signet.chain — Capability chains ✅
- `extend` — create chain or add block (ephemeral key plumbing internal)
- `close` — add final block + seal (ephemeral key discarded, chain frozen)
- `verify` — verify all signatures, chain links, and seal proof
- Blocks are signed envelopes (sign/sign-edn) — reuses signing infrastructure
- Ephemeral private keys never registered, never exposed to developer
- Root authority key must be intentional (no silent auto-generation)
- Block content is opaque EDN — stroopwafel adds Datalog semantics
- Predicates: `chain?`, `open?`, `sealed?`

### signet.session — Noise_KK forward-secret sessions ✅ (0.6.0)
- `Noise_KK_25519_ChaChaPoly_SHA256` — KK handshake pattern, X25519 DH, ChaCha20-Poly1305 AEAD, SHA-256 hashing
- API: `initiator`, `responder`, `write-message`, `read-message`, `established?`
- Pure-functional state machine; no atoms or global state
- Two-message handshake (KK exploits pre-shared static keys); after Split, transport messages are pure AEAD with monotonic nonces per direction
- Forward secrecy via ephemeral-ephemeral DH (`ee` token); mutual authentication via static-static DH (`ss` token) and the cross-DH tokens (`es`, `se`)
- Ed25519 keypair input via the existing birational map (one identity, multiple uses)
- See `docs/05-noise-kk-session-design.md` for the design walkthrough

### signet.encoding — Base64url
- `bytes->base64url` / `base64url->bytes`

### signet.impl — backend facade
- The 16 crypto functions every other namespace calls (`impl/…`), forwarded to the selected backend
- `impl/backend` — `:jca` or `:sodium`
- Unknown backend, or `:sodium` without libsodium/sodium.cljc → loud error at load (no silent fallback)

### signet.impl.sodium — libsodium backend
- Same 16 functions and contracts as `signet.impl.jvm`, on `sodium.core`
- Fixed-size inputs length-checked (libsodium reads them blindly)

### signet.impl.jvm — JCA backend
- Ed25519 key generation, sign, verify
- X25519 key generation, DH key agreement
- Ed25519↔X25519 cross-curve conversion (birational map + SHA-512)
- Seed→public-key derivation via SecureRandom trick (see docs/04)
- SHA-256 hashing

## Implementation Phases
1. **Phase 1 (MVP)**: Key management + Ed25519 signing ✅
2. **Phase 1b**: Capability chains (signet.chain) ✅
3. **Phase 2**: X25519 encryption (signet.box — DH + symmetric encryption)
4. **Phase 3**: SSH import, key discovery, filesystem-based key publishing

## Related Local Projects
- `../stroopwafel` — First consumer (capability-based auth tokens). Adds Datalog on top of signet.chain.
- `../canonical-edn` — Deterministic EDN serialization. Required dependency.
- `../uuidv7.cljc` — Portable UUIDv7. Required dependency.
- `../naclj` — Deprecated NaCl wrapper by Frank. Inspiration for URN key identifiers and DH design.

## Design Docs
- `docs/01-landscape-research.md` — Clojure crypto ecosystem survey
- `docs/02-prior-art-analysis.md` — Analysis of naclj, caesium, stroopwafel, cedn, uuidv7
- `docs/03-design-ideas.md` — Detailed design: namespace structure, key representation, envelope format
- `docs/04-jca-seed-to-public-key-trick.md` — SecureRandom trick for deriving public keys without reflection
- `docs/05-noise-kk-session-design.md` — Noise_KK session design
- `docs/06-box-v2-design.md` — box v2, design only: optional kid/nonce slots, directional HKDF-bound keys, per-message salt; closes finding 7 and the 96-bit nonce limit

## Current state (2026-09-23)

- `main` includes PR #1 (merged): the libsodium backend, trust and
  key-store fixes, dh/edh enforcement, single-use sessions and box v2.
  Build version 0.7.0-SNAPSHOT, installed locally with
  `clojure -T:build install`. Not on Clojars.
- Verified from the installed jar in a scratch consumer (signet's tests
  only, no src): JVM jca 122/572, JVM sodium 122/572 + parity 54/54,
  bb sodium 112/548.
- CI (`.github/workflows/ci.yml`, green): `jca` on Ubuntu JDK 21 + 25
  (`bb test:no-sodium`); `sodium-macos` (Homebrew libsodium; test:jvm-sodium,
  test:bb-sodium, test:jar); `sodium-linux` (libsodium 1.0.22 built from a
  sha256-pinned tarball, since Ubuntu ships 1.0.18; the dynamically linked
  bb 1.13.224, sha256-pinned). sodium.cljc is checked out at the pinned
  `SODIUM_CLJC_REF` and installed with `bb sodium:install`. Every job only
  calls bb tasks.
- **Linux + babashka.ffi needs the dynamically linked bb.** The static
  build, which `setup-clojure` installs on Linux, cannot load any shared
  library. The CI job asserts `file bb` says "dynamically linked".
- Fresh machines: `clojure -P` before `clojure -T:build install` (tools.build
  did not fetch `org.babashka/ffi` itself). Both bb tasks do this.

## Trust model and key-store rules

- **valid** = well-formed, signature ok under the key named in :signer, not
  expired: self-consistency only. **verified** = valid AND the signer/root
  is the expected identity (`verify-edn` `{:signer kid-or-set}`,
  `chain/verify` `{:root kid-or-set}`). **authorized** = policy, which
  belongs to a PDP (stroopwafel), not to signet. The user plans to integrate
  a PDP "everywhere those questions are asked", so keep those seams clean.
- `verify-edn` / `chain/verify` never throw on malformed input. Pass `:now`
  for determinism; without it they read the clock (impure, documented).
- `key/lookup`, `key/kid`, `key/as-public-key` are pure and never register.
  The store holds only deliberately registered keys.
- **Ephemeral keys are never kept longer than needed:** never registered,
  never exposed by the public API, and wiped after use. In `signet.session`:
  `fresh-ephemeral`, `edh` (es/ee/se) vs `dh` (ss), `mix-key` wipes each
  DH output, `split` wipes the ephemeral private key and the handshake
  ck/k. `test/signet/trust_test.clj` asserts absence and zeroing.
- **dh vs edh is enforced, not just named.** Ephemerals are their own
  record types (`EphemeralKeyPair`, `EphemeralPublicKey`, private to
  `signet.session`). `dh` throws `::ephemeral-in-dh` on any ephemeral
  input; `edh` throws `::no-ephemeral-in-edh` when neither side is
  ephemeral. Both use `ex-info`, not assert. Swapping either kind of call
  site fails 10 of the 12 session tests (checked). `key/register!` throws
  `::ephemeral-key` for ephemeral types instead of ignoring them.
- Still registering as a side effect: `key/raw-shared-secret` registers
  both parties, and the keypair and extraction constructors register their
  results. They are user-facing identity operations; revisit.
- **Session states are single-use** (finding 5, closed): each state carries
  a one-shot marker (an atom, since bb has no AtomicBoolean), and
  `consume!` in `signet.session` checks it, runs the op, then
  `compare-and-set!`s it. A stale state throws `::stale-session-state`; the
  losers of a race get their output discarded; a failed read does not
  consume. Disabling `consume!` makes exactly the 4 reuse tests fail
  (checked).
- **Take the gun away:** the public API never hands callers a nonce or an
  ephemeral key (the user's rule: "the creation and usage of nonces were
  hidden from the calling consumer"). `signet.impl*` are `^:no-doc`
  INTERNAL namespaces (raw AEAD with explicit nonces).
- **box v2 implemented** (finding 7 closed): an EDN map with optional
  `:from`/`:to` kid slots (default on), an `:aad` slot (any EDN) and a
  24-byte nonce. The key is HKDF(DH, salt = nonce, info = v2 ‖ sender_x ‖
  recipient_x), so it is directional and unique per message. The
  cedn-canonical header is the AAD. v1 was dropped (no reader or writer).
  See `docs/06-box-v2-design.md` and `encryption_test.clj` (14 tests,
  injection-checked).

## Testing, lint, format

```bash
bb test:jvm          # full suite, JCA backend (clojure -M:test): 102 tests / 436 assertions
bb test:jvm-sodium   # full suite, libsodium backend + JCA-vs-libsodium parity (54 checks)
bb test:bb-sodium    # full suite on babashka, libsodium backend: 93 / 415 (all but secp256k1)
bb smoke             # bb smoke suite (JCA): 9 tests
bb test:no-sodium    # lint + fmt + JCA suite + bb smoke (no native libsodium needed)
bb test:all          # test:no-sodium + test:jvm-sodium + test:bb-sodium
bb sodium:install [dir]  # clojure -P + tools.build install of sodium.cljc (default ../sodium.cljc)
bb test:jar          # install signet's jar, run its tests from a scratch consumer: jca, sodium + parity, bb
bb lint / bb fmt     # clj-kondo / cljfmt on every Clojure file
```

`.clj-kondo/config.edn` lints only the `:clj` branch of `.cljc` files, because
the `:cljs` branches are stubs. Remove that when ClojureScript lands. A
user-level Claude Code hook runs cljfmt + clj-kondo after every edit.
