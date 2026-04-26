# Signet — CLJC 25519 Crypto Library

## Project Overview
Portable CLJC library for Ed25519/X25519 elliptic curve cryptography: request signing and encryption with EDN-native message formats.

## Architecture — Two Concerns
- **signet**: Crypto primitives — key management, request signing, encryption (DH + symmetric)
- **stroopwafel**: Capability semantics — bearer tokens, Datalog policy, built on signet

## Key Decisions Made
- **Name**: signet (like a signet ring — personal key for signing/sealing)
- **Platform strategy**: Java JCA on JVM (Ed25519 Java 15+, X25519 Java 11+), WebCrypto on JS (all browsers 2025+), @noble/curves as JS fallback
- **Dependencies**: canonical-edn (cedn) for deterministic serialization, uuidv7 for request IDs. No libsodium, no Bouncy Castle.
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
