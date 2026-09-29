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
  - `:sodium` — `signet.impl.sodium`, libsodium via `nacljc.core` (the backend keeps the name `:sodium`: it names libsodium, the native engine, not the wrapper) (github.com/franks42/nacljc, `com.github.franks42/nacljc 0.6.0` from Clojars via the `:sodium` alias; the version in bb.edn's test:bb-sodium and test/signet/consumer_check.clj (test:jar) must match; babashka.ffi). To test an unreleased nacljc, swap in `{:local/root "../nacljc"}`. Needs libsodium >= 1.0.19, JDK 25+ with `--enable-native-access=ALL-UNNAMED`, bb >= 1.13.220. Runs the full suite on bb too. Byte-identical output to `:jca` (`test/signet/backend_parity.clj`).
  - ClojureScript: not implemented (every `:cljs` branch throws). The browser plan is libsodium.js (see `../nacljc/docs/feasibility.md`).
- **Dependencies**: canonical-edn (cedn) 1.6.1 for deterministic serialization, uuidv7 0.7.3 for request IDs (see README "Compatibility"). Bouncy Castle for secp256k1 only (JVM). nacljc 0.6.0 from Clojars for the `:sodium` backend (alias `:sodium`).
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

### signet.session — Noise_KK forward-secret sessions ✅ (0.6.0; on vault handles in 0.9.0)
- `Noise_KK_25519_ChaChaPoly_SHA256` — KK handshake pattern, X25519 DH, ChaCha20-Poly1305 AEAD, SHA-256 hashing
- API: `initiator`, `responder` (local static = vault handle; peer = public key or kid), `write-message!`, `read-message!`, `established?`, `close!`, `with-conclave`
- Wire-compatible with other Noise implementations since 0.9.0 (prologue order fixed); `test/signet/noise_vectors_test.clj` checks the cacophony and snow vectors
- Single-use state values; secrets (ck, k, transport keys, ephemerals) are vault session entries, the state holds handles only. `consume!` destroys what the next state doesn't need (or, on failure/lost race, what the call created); `close!` destroys the whole session from any state (docs/08)
- Two-message handshake (KK exploits pre-shared static keys); after Split, transport messages are pure AEAD with monotonic nonces per direction
- Forward secrecy via ephemeral-ephemeral DH (`ee` token); mutual authentication via static-static DH (`ss` token) and the cross-DH tokens (`es`, `se`)
- Ed25519 keypair input via the existing birational map (one identity, multiple uses)
- See `docs/05-noise-kk-session-design.md` for the design walkthrough

### signet.encoding — Base64url
- `bytes->base64url` / `base64url->bytes`

### signet.vault — secrets by reference (0.8.0; docs/07)
- Handles (`KeyHandle`: kid + vault id); providers `:memory` and `:sodium` (`signet.vault.sodium`, nacljc guarded memory)
- `generate-signing-key!`, `generate-encryption-key!`, `import-*-key!`, `export-secret` (ack), `destroy!`, `public-key`, `lookup`, `handle(s)`, defaults, `import-password!`
- Session entries (Noise secrets), internal entries (a vault file's master key), the gate (read/write lock), `note-use!` (auto-lock hook); `^:no-doc` internals for signet.password / signet.vault.file

### signet.shared — shared (DH-derived) symmetric keys as handles (0.8.0)
- `shared-key!`, `seal`/`open` (directional, key-committing), `mac`

### signet.encryption — box v2 (docs/06)
- `box`/`unbox` with vault handles; optional `:from`/`:to` kids, `:aad`, 24-byte nonce, HKDF-bound directional key

### signet.password — password-derived keys (0.10.0, slice 1 of docs/10)
- `password-key!` (Argon2id; password bytes wiped; key kept in the vault), `seal`, `open` (with the handle or the password)
- libsodium backend only; JCA throws `:signet.impl/unsupported`

### signet.vault.file — vault files (0.10.0, slice 2 of docs/10)
- `create!`, `open!` (locked), `unlock!`, `lock!`, `save!` (or `:auto-save`), `change-password!`, `status`
- Optional recovery key: `add-recovery-key!` (ack; returns `SIGNET-RK1-…` bytes once), `unlock-with-recovery-key!`, `reset-password!` (only after a recovery unlock), `remove-recovery-key!`
- password → Argon2id → wraps the random master key (an internal vault entry) → per-save HKDF key encrypts the body and wraps each identity key (`impl/wrap-material`, nacljc `wrap-secret`); header is the body's AAD
- Saves identity keys, public side, default signing key; not shared/password keys or sessions. Locked vault: `:signet.vault/vault-locked` for key use and for writes
- Auto-lock (docs/11): `:idle-timeout`/`:max-unlocked`, `:on-dirty` (:save default), `:on-lock`; lazy check on each key use (`vault/note-use!` → file state `:on-use`) + a daemon timer thread
- Passwords: bytes, a nacljc secret, or a password handle (`vault/import-password!`, `:uses` default 1 / `:keep`); all consumed; `vault/password-input?`
- Each vault has a gate (read/write lock, fair Semaphore + thread-local `*held*`): lending material = read, destroying = write; destroy inside an operation throws `::destroy-inside-operation`

### signet.impl — backend facade
- The 22 crypto functions every other namespace calls (`impl/…`), forwarded to the selected backend
- `impl/backend` — `:jca` or `:sodium`
- Unknown backend, or `:sodium` without libsodium/nacljc → loud error at load (no silent fallback)

### signet.impl.sodium — libsodium backend
- Same 22 functions and contracts as `signet.impl.jvm`, on `nacljc.core`
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
3. **Phase 2**: X25519 encryption (`signet.encryption`, box v2) ✅
4. **Phase 3**: SSH import ✅ (`signet.ssh`); key discovery and filesystem-based key publishing not done
5. Since then: the vault and handles (0.8.0), sessions on handles (0.9.0), password unlocking and vault files (0.10.0) ✅

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
- `docs/08-sessions-on-handles-plan.md` — 0.9.0 implementation plan: session secrets as vault session entries, `close!` by session, `with-conclave`; phase 0 (Noise known-answer vectors) done
- `docs/09-e2e-through-proxies.md` — design note (2026-09-27): application-layer E2E through TLS-terminating proxies (Cloudflare etc.): threat levels, the code-delivery and key-anchoring problems, existing standards (OHTTP/HPKE, DPoP, client-side payment encryption), pieces we have and a possible first slice. Not built.
- `docs/10-password-unlocking.md` — password unlocking and vault persistence (2026-09-27): key layers (password -> Argon2id -> master key -> entries), the vault file as a suite, lock/unlock, the optional recovery key; decisions taken; built in 0.10.0 (`signet.password`, `signet.vault.file`), with "As built" notes.
- `docs/11-auto-lock-and-password-input.md` — design (2026-09-27): the vault destroy race (a bug to fix first), auto-lock (activity clock, lazy check + timer, :on-dirty), nacljc.tty password reader into guarded memory, passwords as secrets and as handles. Built in 0.10.0 (nacljc.tty in nacljc 0.6.0), with "As built" notes.
- `docs/12-agent-design.md` — design (2026-09-27): secrets in a separate process; operation-level providers (phase 0), an ssh-agent client provider (sign-only), the signet agent (Unix socket, peer check, CEDN protocol), policy and the PDP seam. Not built.

## Current state (2026-09-28)

**Released: signet 0.10.0 (2026-09-28), on nacljc 0.6.0. main is
0.11.0-SNAPSHOT** (CHANGELOG has an empty `## 0.11.0 (unreleased)`).
CI green on both repos.

What 0.10.0 brought (details in CHANGELOG.md):
- Password unlocking, docs/10: `signet.password` (password-derived key
  handles, seal/open) and `signet.vault.file` (vault files: create!/open!/
  unlock!/lock!/save!, :auto-save, change-password!, optional recovery key
  `SIGNET-RK1-…`).
- docs/11: the destroy-race fix (per-vault gate: read/write lock on a fair
  Semaphore, `::destroy-inside-operation`), auto-lock (`:idle-timeout`,
  `:max-unlocked`, `:on-dirty`, `:on-lock`, timer thread + lazy check),
  passwords as nacljc secrets (from `nacljc.tty/read-password`), password
  handles (`vault/import-password!`, one use by default).
- Review findings 11/12 (keyword errors in `chain/verify`; `verify-edn`
  checks `:type`), doc notes (message-1 replay, `NACLJC_LIBSODIUM`).

Earlier releases, briefly: 0.7.0 first Clojars release (libsodium backend,
naming/purity batch); 0.8.0 the vault and handles; 0.9.0 sessions on vault
handles, `close!`, `with-conclave`, Noise prologue fix, key records
deprecated; 0.9.1–0.9.4 nacljc bumps, purity/throws docstrings on every
function, Devin review fixes (`docs/review-devin-20260926.md`,
`test/signet/seams_test.clj`).

### Possible next steps (none chosen yet; ask the user)

- **docs/12 phase 0: operation-level providers** (refactor, no behavior
  change): providers offer operations instead of lending material. Useful
  on its own as the seam for hardware tiers. But the agent work (docs/12:
  ssh-agent client provider, the signet agent with an nREPL-message-model
  EDN protocol, no eval) is **on the back burner** by the user's decision
  (2026-09-27); ask before starting any of it.
- **Open design topics in docs/07:** AEGIS suites, box key commitment,
  post-quantum (X-Wing is in nacljc), names for keys, chain attenuation,
  hardware tiers. docs/09 (E2E through TLS-terminating proxies) has a
  possible first slice, not planned.
- Small: rollback of a vault file is not detected (documented); Unicode
  normalization of passwords (documented; a future option).
- **Back burner:** CI for distributions with libsodium < 1.0.19 (Ubuntu
  1.0.18); the agent (docs/12).

### How we work (the user's preferences)

- Commit and push only when asked; the user usually asks ("push it",
  "release X"). No external users yet: breaking changes are fine, but
  flagged in the CHANGELOG.
- Bugs: a failing-first test, then the fix; every guard injection-checked
  (remove it, see a test fail). External reviews: verify each finding by
  reproduction, add a resolution section.
- Discussion turns ("no coding", "discuss") get design answers, often
  written up as docs/NN afterwards.
- Audience (docs/07): signet protects developers from mistakes and
  ordinary exposure; determined adversaries with code execution are
  documented, not targeted.

### Release procedure

Set build.clj's version and the CHANGELOG heading `## X.Y.Z (YYYY-MM-DD)`;
`bb release-check`, `bb test:all`, `bb test:jar`; commit "Release X.Y.Z",
push, wait for CI green; tag `vX.Y.Z` and push the tag
(`.github/workflows/release.yml` runs the tests, deploys to Clojars, runs
`bb test:clojars X.Y.Z` against the published jar, creates the GitHub
release); then bump build.clj to the next -SNAPSHOT and add an
`## X.Y.Z (unreleased)` heading. A signet release that needs a new nacljc:
release nacljc first, then pin it in deps.edn, bb.edn (test:bb-sodium) and
test/signet/consumer_check.clj.

### CI and environment notes

- CI (`.github/workflows/ci.yml`): `jca` on Ubuntu JDK 21 + 25
  (`bb test:no-sodium`); `sodium-macos` (Homebrew libsodium;
  test:jvm-sodium, test:bb-sodium, test:jar); `sodium-linux` (libsodium
  1.0.22 built from a sha256-pinned tarball, since Ubuntu ships 1.0.18;
  the dynamically linked bb 1.13.224, sha256-pinned). Every job only calls
  bb tasks.
- **Linux + babashka.ffi needs the dynamically linked bb.** The static
  build, which `setup-clojure` installs on Linux, cannot load any shared
  library. The CI job asserts `file bb` says "dynamically linked".
- babashka lacks some JDK classes (e.g. `ReentrantReadWriteLock`,
  `StampedLock`, `java.security.InvalidKeyException`): check with
  `bb -e` before relying on one.
- No Docker on the user's laptop: Linux-only behavior is verified in CI.
- Fresh machines: `build.clj` adds Maven Central and Clojars back to its
  `:root nil` basis, else `clojure -T:build install` fails.

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
  never on a vault's public side or in `handles`, never exposed by the
  public API, and destroyed after use. In `signet.session` (0.9.0):
  `fresh-ephemeral` makes a vault session entry, `edh` (es/ee/se) vs `dh`
  (ss), `mix-key!` (via `vault/hkdf-pair!`) destroys each DH output, and
  `consume!` destroys the ephemeral and the handshake ck/k after Split.
  `test/signet/trust_test.clj` asserts absence and destruction.
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
bb test:jvm          # full suite, JCA backend (clojure -M:test): 240 tests / 1096 assertions
bb test:jvm-sodium   # full suite, libsodium backend (240 / 1304) + JCA-vs-libsodium parity
bb test:bb-sodium    # full suite on babashka, libsodium backend: 230 / 1275 (all but secp256k1)
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

Every function, public and private, follows this since 0.9.3 (a check:
each docstring's first paragraph says `Pure`, `Impure: …` or `Never
returns`). The private throw-only helpers `ssh/bad-key!` and `shared/meta!`
were renamed (`throw-bad-key`, `checked-meta`).
