# Signet — CLJC 25519 Crypto Library

## Project Overview
Portable CLJC library for Ed25519/X25519 elliptic curve cryptography: message signing and encryption with EDN-native message formats.

## Key Decisions Made
- **Name**: signet (like a signet ring — personal key for signing/sealing)
- **Platform strategy**: Java JCA on JVM (Ed25519 Java 15+, X25519 Java 11+), WebCrypto on JS (all browsers 2025+), @noble/curves as JS fallback
- **Dependencies**: canonical-edn (cedn) for deterministic serialization, uuidv7 for request IDs. No libsodium, no Bouncy Castle.
- **Key representation**: `defrecord` with `:type` field convention. Records are maps (cedn-compatible), `:type` keyword enables multimethod dispatch. Use `derive` to bridge record class → keyword hierarchy so one `defmethod` handles both.
- **"seal" renamed to "close"**: `close`/`closed?` = sign-and-discard (proves key possession, destroys delegation ability). Analogous to closing a stream.
- **Namespace prefix**: `signet.*` — `signet.key`, `signet.sign`, `signet.box`, `signet.hash`, `signet.envelope`, `signet.encoding`
- **Type tags**: `:signet/ed25519-keypair`, `:signet/x25519-keypair`, `:signet/signed`, `:signet/closed`, `:signet/encrypted`

## Implementation Phases
1. **Phase 1 (MVP)**: Key management + Ed25519 signing (JVM first, then JS)
2. **Phase 2**: X25519 encryption
3. **Phase 3**: Advanced (key store, SSH import, sealed boxes, multi-recipient)

## Related Local Projects
- `../stroopwafel` — First consumer (capability-based auth tokens). Defines crypto requirements.
- `../canonical-edn` — Deterministic EDN serialization. Required dependency.
- `../uuidv7.cljc` — Portable UUIDv7. Required dependency.
- `../naclj` — Deprecated NaCl wrapper by Frank. Inspiration for protocol design.
- `../caesium` — libsodium wrapper. Inspiration for API simplicity.

## Design Docs
- `docs/01-landscape-research.md` — Clojure crypto ecosystem survey
- `docs/02-prior-art-analysis.md` — Analysis of naclj, caesium, stroopwafel, cedn, uuidv7
- `docs/03-design-ideas.md` — Detailed design: namespace structure, key representation, envelope format, API sketch

## defrecord + :type Pattern
```clojure
(defrecord Ed25519KeyPair [type public secret kid])
(derive Ed25519KeyPair :signet/ed25519-keypair)
(defmulti from-map (fn [m] (or (:type m) (type m))))
(defmethod from-map :signet/ed25519-keypair [m] (map->Ed25519KeyPair m))
;; Works for both plain maps (from EDN) and existing records
```
