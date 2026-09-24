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
  - `:sodium` — `signet.impl.sodium`, libsodium via `nacljc.core` (the backend keeps the name `:sodium`: it names libsodium, the native engine, not the wrapper) (github.com/franks42/nacljc, `com.github.franks42/nacljc 0.1.0` from Clojars via the `:sodium` alias; the version in bb.edn's test:bb-sodium and test:jar must match; babashka.ffi). To test an unreleased nacljc, swap in `{:local/root "../nacljc"}`. Needs libsodium >= 1.0.19, JDK 25+ with `--enable-native-access=ALL-UNNAMED`, bb >= 1.13.220. Runs the full suite on bb too. Byte-identical output to `:jca` (`test/signet/backend_parity.clj`).
  - ClojureScript: not implemented (every `:cljs` branch throws). The browser plan is libsodium.js (see `../nacljc/docs/feasibility.md`).
- **Dependencies**: canonical-edn (cedn) 1.5.2 for deterministic serialization, uuidv7 0.7.1 for request IDs (bumped from 1.2.0 / 0.5.0 in 0.7.0; see README "Compatibility"). Bouncy Castle for secp256k1 only (JVM). nacljc for the `:sodium` backend (alias `:sodium`: local snapshot jar, not published).
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
- Key store with `lookup`, `register!`, `unregister!`; pure constructors and
  `!` twins (`signing-keypair!`, `encryption-keypair!`) that also register
- Default signing/encryption keypairs, set explicitly
  (`set-default-*!`, `ensure-default-signing-keypair!`)
- Predicates: `signing-keypair?`, `signing-public-key?`, etc.

### signet.sign — Request signing
- Low-level: `sign` / `verify` (bytes in, bytes out)
- High-level: `sign-edn` / `verify-edn` (EDN envelopes with cedn + UUIDv7)
- Zero-config: `(sign-edn! payload)` uses the default keypair, creating and
  registering one if needed; `sign-edn` always takes an explicit key
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
- API: `initiator`, `responder`, `write-message!`, `read-message!`, `established?`
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
- Unknown backend, or `:sodium` without libsodium/nacljc → loud error at load (no silent fallback)

### signet.impl.sodium — libsodium backend
- Same 16 functions and contracts as `signet.impl.jvm`, on `nacljc.core`
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
- `docs/07-secret-handles-design.md` — DRAFT: secrets by reference (handles + vault + providers: memory, sodium secure memory, WebCrypto, agent); code never sees secret bytes; also records the 2026-09-23 naming/twin-rule decisions for 0.7.0

## Current state (2026-09-23)

- `main` is 0.7.0 ready for release, the first Clojars release. It adds
  PR #1 (libsodium backend, trust and key-store fixes, dh/edh enforcement,
  single-use sessions, box v2) and the naming/purity batch: pure key
  functions with `!` twins, `register!` sets no defaults, `sign-edn!`,
  `write-message!`/`read-message!`, typed errors (`:type`) everywhere,
  redacted printing, strict SSH import. See CHANGELOG.md.
- **Release:** a `vX.Y.Z` tag runs `.github/workflows/release.yml`. It
  runs `bb release-check` and both backends' tests, deploys, then runs
  `bb test:clojars X.Y.Z` (signet's tests against the jar from Clojars,
  empty local repo) before the GitHub release.
- **Next (0.8.0):** secrets behind handles in a vault
  (`docs/07-secret-handles-design.md`).
- Verified from the installed jar in a scratch consumer (`bb test:jar`,
  signet's tests only, no src): JVM jca 131/652, JVM sodium 131/652 +
  parity 54/54, bb sodium 121/628.
- CI (`.github/workflows/ci.yml`, green): `jca` on Ubuntu JDK 21 + 25
  (`bb test:no-sodium`); `sodium-macos` (Homebrew libsodium; test:jvm-sodium,
  test:bb-sodium, test:jar); `sodium-linux` (libsodium 1.0.22 built from a
  sha256-pinned tarball, since Ubuntu ships 1.0.18; the dynamically linked
  bb 1.13.224, sha256-pinned). nacljc 0.1.0 comes from Clojars. Every job
  only calls bb tasks.
- **Linux + babashka.ffi needs the dynamically linked bb.** The static
  build, which `setup-clojure` installs on Linux, cannot load any shared
  library. The CI job asserts `file bb` says "dynamically linked".
- Fresh machines: `build.clj`'s `:root nil` basis dropped Maven Central and
  Clojars (they live in the root deps.edn), so `clojure -T:build install`
  could only use jars already in ~/.m2 ("Could not find artifact"). Fixed
  by adding both repositories back in `build.clj`.

## Trust model and key-store rules

- **valid** = well-formed, signature ok under the key named in :signer, not
  expired: self-consistency only. **verified** = valid AND the signer/root
  is the expected identity (`verify-edn` `{:signer kid-or-set}`,
  `chain/verify` `{:root kid-or-set}`). **authorized** = policy, which
  belongs to a PDP (stroopwafel), not to signet. The user plans to integrate
  a PDP "everywhere those questions are asked", so keep those seams clean.
- `verify-edn` / `chain/verify` never throw on malformed input. Pass `:now`
  for determinism; without it they read the clock (impure, documented).
- **Only `!` functions write the key store or the defaults** (0.7.0). All
  constructors and conversions are pure; the `!` twins (`signing-keypair!`,
  `encryption-keypair!`, `ssh/load-keypair!`) register and return the key.
  `register!` never sets a default; `set-default-signing-keypair!` and
  `ensure-default-signing-keypair!` (CAS, exactly one default under races)
  do. `sign-edn` needs an explicit key; `sign-edn!` uses/creates the
  default. Tested: `pure-functions-leave-store-and-defaults-alone` (a table
  over every pure fn), `registering-twins`; each guard injection-checked.
- Key records print redacted (`#signet/key {… :d "<redacted>"}`), and error
  data never carries key bytes (checked structurally: no byte array in
  ex-data). Serialising a key record as data still exposes `:d` — the
  vault (0.8.0) fixes that.
- **Ephemeral keys are never kept longer than needed:** never registered,
  never exposed by the public API, and wiped after use. In `signet.session`:
  `fresh-ephemeral`, `edh` (es/ee/se) vs `dh` (ss), `mix-key!` wipes each
  DH output, `split!` wipes the ephemeral private key and the handshake
  ck/k. `test/signet/trust_test.clj` asserts absence and zeroing.
- **dh vs edh is enforced, not just named.** Ephemerals are their own
  record types (`EphemeralKeyPair`, `EphemeralPublicKey`, private to
  `signet.session`). `dh` throws `::ephemeral-in-dh` on any ephemeral
  input; `edh` throws `::no-ephemeral-in-edh` when neither side is
  ephemeral. Both use `ex-info`, not assert. Swapping either kind of call
  site fails 10 of the 12 session tests (checked). `key/register!` throws
  `::ephemeral-key` for ephemeral types instead of ignoring them.
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
bb test:jvm          # full suite, JCA backend (clojure -M:test): 131 tests / 650 assertions
bb test:jvm-sodium   # full suite, libsodium backend + JCA-vs-libsodium parity (54 checks)
bb test:bb-sodium    # full suite on babashka, libsodium backend: 121 / 626 (all but secp256k1)
bb smoke             # bb smoke suite (JCA): 9 tests
bb test:no-sodium    # lint + fmt + JCA suite + bb smoke (no native libsodium needed)
bb test:all          # test:no-sodium + test:jvm-sodium + test:bb-sodium
bb test:jar          # install signet's jar, run its tests from a scratch consumer: jca, sodium + parity, bb
bb test:clojars V    # the same against release V from Clojars (empty local repo)
bb release-check     # X.Y.Z only, CHANGELOG section required
bb lint / bb fmt     # clj-kondo / cljfmt on every Clojure file
```

`.clj-kondo/config.edn` lints only the `:clj` branch of `.cljc` files, because
the `:cljs` branches are stubs. Remove that when ClojureScript lands. A
user-level Claude Code hook runs cljfmt + clj-kondo after every edit.

## Naming: purity, `!` and exceptions

The same convention holds in canonical-edn, uuidv7, nacljc and signet
(decided 2026-09-23).

- **`!` means the call writes state that outlives it.** That covers
  atoms, volatiles and transients, global registries (such as signet's key
  store), the contents of an argument (wiping a buffer, consuming a
  session state), native memory the caller owns, files, databases and
  network sends. This is clojure.core's line (`reset!`, `swap!`, `conj!`),
  extended to external writes, as in the Clojure style guide's `save-user!`.
- **Reads get no `!`, even impure ones:** the clock, the random
  generator (drawing is not a write), the environment, system properties
  and file reads. Printing and logging are diagnostic and get no `!`
  either. The docstring says what the function reads.
- **`!` never means "may throw".** That is the Elixir and Rails meaning,
  and it is not used here. An exception signals abnormal execution, and
  Clojure never forces a caller to catch one, so throwing is documented,
  not encoded in the name.
- **Docstrings** state these facts in their first paragraph, in fixed
  wording:
  - `Impure: <what it reads or writes>.` for every impure function.
  - `Throws ex-info {:type ::x} when …`, listing every `:type`. The
    ex-data `:type` is the contract; callers dispatch on it, never on the
    message.
  - `Never throws: …` for functions that promise it, such as verifiers
    returning `{:valid? false …}`.
- **Validators** that return their argument or throw are named `check-…`
  (for example `check-bytes`). Helpers whose only job is to throw are named
  `throw-…`.
- **Prefer a pure core with a thin `!` shell** (functional core, imperative
  shell). When a function both computes and writes, offer the pure one and
  make the write a separate, explicit `!` call, rather than only renaming.

Existing names that break this rule were inventoried on 2026-09-23 and
have not been renamed yet.
