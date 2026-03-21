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

### signet.chain — Capability chains (designed, not yet implemented)
- `extend` — add block, chain stays open (ephemeral key plumbing internal)
- `close` — add final block + seal (ephemeral key discarded)
- `verify` — verify chain integrity
- Developer never touches ephemeral keys

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
2. **Phase 2**: signet.chain (capability chains) + X25519 encryption (signet.box)
3. **Phase 3**: SSH import, key discovery, filesystem-based key publishing

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
