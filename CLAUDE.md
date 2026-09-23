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
- **Dependencies**: canonical-edn (cedn) for deterministic serialization, uuidv7 for request IDs. Bouncy Castle for secp256k1 only (JVM). sodium.cljc for the `:sodium` backend (alias `:sodium`: local snapshot jar, not published).
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

## Testing, lint, format

```bash
bb test:jvm          # full suite, JCA backend (clojure -M:test): 102 tests / 436 assertions
bb test:jvm-sodium   # full suite, libsodium backend + JCA-vs-libsodium parity (54 checks)
bb test:bb-sodium    # full suite on babashka, libsodium backend: 93 / 415 (all but secp256k1)
bb smoke             # bb smoke suite (JCA): 9 tests
bb lint / bb fmt     # clj-kondo / cljfmt on every Clojure file
```

`.clj-kondo/config.edn` lints only the `:clj` branch of `.cljc` files, because
the `:cljs` branches are stubs. Remove that when ClojureScript lands. A
user-level Claude Code hook runs cljfmt + clj-kondo after every edit.
