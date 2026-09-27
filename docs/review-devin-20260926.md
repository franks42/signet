# Signet — code review

Date: 2026-09-26. Reviewed `main` @ `a57fd9b` (0.10.0-SNAPSHOT, i.e. the
0.9.3 release plus docs). Scope: all of `src/`, `test/`, build files, CI
workflows, README/CHANGELOG/design docs. No code changed.

## Overall assessment

This is an unusually disciplined codebase for a personal library: a clear
trust vocabulary (valid / verified / authorized) applied consistently, a
real threat model (docs/07), secrets-by-reference via vault handles,
single-use session states, enforced dh/edh separation, typed ex-info
errors, Noise known-answer vectors from two independent implementations,
and a release pipeline that tests the artifact actually published to
Clojars. The design docs explain *why*, not just *what*.

The headline numbers in CLAUDE.md are accurate — verified locally:

| Task | Claimed | Got |
|---|---|---|
| `bb test:no-sodium` (lint + fmt + JCA + bb smoke) | 183/986, 9/26 | 183/986, 9/26, lint+fmt clean |
| `clojure -M:test:sodium` | 183/1000 | 183/1000 |
| `bb test:bb-sodium` (nacljc 0.3.2) | 173/974 | 173/974 |

The findings below are mostly edge cases at the seams between the vault,
shared keys, and the older key-record layer — plus one functional bug
worth fixing soon.

## Findings

### 1. Shared-key handles break `unbox` nondeterministically (verified)

A shared key created with `shared/shared-key!` is stored in the provider
under alg `:shared`. `vault/handle`/`vault/handles` exclude session
entries but not shared keys (`src/signet/vault.cljc` ~L222-239), so a
shared-key handle appears wherever "keys the vault holds" are enumerated.

Downstream code is not ready for it:

- `vault/public-key` returns nil for a shared kid (~L394-400), so
  `key/encryption-public-key` on it throws `IllegalArgumentException:
  No method in multimethod`.
- `vault/x25519-dh` `case`s on `(-alg p kid)` with only `:x25519` /
  `:ed25519` clauses (~L425) → `IllegalArgumentException:
  No matching clause: :shared`.
- `unbox`'s outer catch maps any exception to `{:valid? false
  :error :malformed}` (`src/signet/encryption.cljc` ~L254).

Consequence, verified by REPL: with a shared key in `:default`,
`(unbox :default box)` fails ~30 % of runs with `:error :malformed` even
for a perfectly valid box *with* `:to` and `:from` slots — the
`same-identity?` filter evaluates candidates in hash-set order and throws
on the shared handle before reaching the real recipient. With `:to?
false` it is worse. `(unbox shared-handle box)` and `(enc/box
shared-handle …)` likewise fail with raw `IllegalArgumentException`
rather than a typed error.

The encryption tests never create a shared key and the shared tests never
unbox, so this seam is untested.

Suggested direction (either suffices): have `recipient-candidates` /
`has-private?` restrict candidates to `#{:ed25519 :x25519}` via
`vault/algorithm`, and/or make `vault/x25519-dh` and `vault/public-key`
throw a typed `::wrong-algorithm` for non-identity kids (matching the
`vault/sign` behaviour). `session/initiator` already does the right thing
here — a shared handle gives a clean `::no-private-key`.

### 2. `(chain/close token content)` skips the `sealed?` check (verified)

The 2-arity calls `extend-chain` directly, bypassing the `sealed?` guard
that the 1-arity has (`src/signet/chain.cljc` ~L294-297). On a sealed
token, `proof-signer` treats the `{:sealed true :signature …}` map as a
seed and the failure surfaces as a raw `ArrayStoreException` deep inside
`arraycopy` instead of `ex-info {:type ::sealed}`. Verified:

```
(chain/close sealed)            → :signet.chain/sealed
(chain/close sealed {:more 2})  → ArrayStoreException (no ex-data)
```

### 3. `export-token` + `close` leaves a live proof key in the vault (verified)

`export-token` copies the seed out (`vault/export-secret` keeps the
vault's copy). `close` only destroys the proof when it is a handle
(`src/signet/chain.cljc` ~L290). So the natural flow — export a token to
send it, then close — leaves the chain's last ephemeral key alive in the
vault: it is still in `handles`, still signs via `vault/sign`, and can
still produce a forked extension of the "sealed" chain. Verified by REPL.

This weakens the documented seal guarantee ("the key is gone") for
exactly the sendable-token workflow. Options: document that the exported
twin is not destroyed, recommend `import-token!` + `close` for the local
copy, or have `export-token` note/track the relationship so `close` can
destroy the vault copy too.

### 4. Backend parity breaks on malformed public keys (verified)

`ed25519-pub->x25519-pub`:

- JCA (`src/signet/impl/jvm.clj` ~L177-194) does no point validation — it
  treats the 32 bytes as a y-coordinate. For y = 1 the denominator is
  zero → `ArithmeticException: BigInteger not invertible`. For other
  invalid points it returns a garbage-but-deterministic X25519 key.
- Sodium (`signet.impl.sodium` → `na/ed25519->x25519-public-key`) throws
  `ex-info {:type :nacljc.core/invalid-public-key}` for both cases.

Verified on both backends. So a crafted `urn:signet:pk:ed25519:` kid
reaches `session/initiator` as `ArithmeticException` on JCA (vs a typed
error on sodium), and on JCA a DH is actually computed against the
nonsense point — AEAD still fails downstream, so this is contained, but
the backends disagree about *whether* these inputs error at all.
`x25519-dh` is similar in spirit: JCA surfaces raw JCA exceptions for
low-order points vs nacljc's `::low-order-point`. The "byte-identical"
claim holds for valid keys; the error contract does not hold for invalid
ones.

### 5. Two kid parsers disagree on validity

`key/lookup`'s private `parse-kid` validates the decoded length per
algorithm (`src/signet/key.cljc` ~L167-181); the public `kid->public-key`
(~L612-626) does not — it happily builds an `Ed25519PublicKey` from a
5-byte payload (verified). So a kid that `lookup` refuses is accepted by
`kid->public-key`, and the malformed record then fails later with raw
exceptions (as in finding 4). `kid->hex` and `hex->kid` inherit the same
laxness. Align them: validate length (and ideally re-use one parser).
`kid->public-key` also throws raw exceptions rather than ex-info with a
`:type`, against the project's own error convention.

### 6. `sign/verify` does not accept a vault handle

`sign/sign` routes handles to `vault/sign`, but `verify` calls
`key/public-key`, which `case`s on `(:crv k)` — a `KeyHandle` has no
`:crv` → `IllegalArgumentException` (verified). Asymmetric and a likely
caller mistake, since "handles everywhere" is the 0.8+ direction. Either
resolve `(vault/public-key k)` for handles or throw a typed error.

### 7. Wrong-type inputs produce raw exceptions instead of typed errors

A recurring pattern — `case`/`defmulti` dispatch on `:type`/`:crv`/`:alg`
has no default clause, so wrong-but-plausible inputs throw bare
`IllegalArgumentException` ("No matching clause" / "No method in
multimethod") rather than ex-info with a `:type`:

- `session/initiator`/`responder` with a secp256k1 kid or a public key of
  a non-25519 curve (verified; `resolve-remote` only string-checks kids,
  `->x25519-public-bytes` then fails).
- `shared-key!` with a non-key `their-public` (`x25519-pub` →
  `key/encryption-public-key` multimethod).
- `vault/register-public-key!` with a non-key (`key/public-key` case).
- The shared-handle paths of finding 1.

Each call site is a public API entry point; a `check-`-style guard with a
typed `:type` (e.g. `::bad-key-type`) would fit the convention.

### 8. `register!` on a secp256k1 private key is a silent no-op

The docstring says "such keys register without a kid", but since the
store is keyed by kid and `kid-str` is nil, the `swap!` is skipped and
**nothing is stored** (`src/signet/key.cljc` ~L139-165) — while still
returning the key as if it registered. Either the doc should say it is a
no-op, or it should throw a typed error so callers notice.

### 9. JCA `hkdf-sha-256` has no RFC 5869 length bound

The expand counter is one byte; `length` above 255·32 = 8160 bytes wraps
the counter silently and produces wrong output (`src/signet/impl/jvm.clj`
~L274-298). All internal callers ask for ≤64 bytes so nothing breaks
today, but `signet.impl` is public and `vault/hkdf-pair!` passes lengths
through. Throw for `length > 8160` (nacljc presumably already does — a
parity point).

### 10. `open-aead` collapses every failure into `::authentication-failed`

`src/signet/session.cljc` ~L192-206 wraps *any* exception from
`vault/aead-decrypt` — including `::destroyed-key` and `::unknown-vault`
(a concurrently closed session, a removed vault) — as
`::authentication-failed`. Operationally fine but misleading for
debugging; consider re-throwing typed vault errors unchanged.

### 11. `chain/verify` error representation is inconsistent with `verify-edn`

`verify-edn` returns keyword `:error` reasons (`:bad-signature`,
`:expired`, …); `chain/verify` returns English strings
(`src/signet/chain.cljc` ~L438-463, ~494-506). Also the `:blocks` field
contains full `verify-edn` result maps on failure but only `:message`
maps on success. Keyword `:error` types and a uniform `:blocks` shape
would make the result easier to consume programmatically.

### 12. `verify-edn` ignores the envelope's `:type`

Any map with a well-formed `:envelope` + valid `:signature` verifies,
whether or not it says `:type :signet/signed`. Harmless (the type tag is
outside the signed bytes anyway — also worth a doc note that it is
unauthenticated), but `verify-edn` could reject wrong `:type`s early like
`unbox`/`open` do for theirs.

### 13. Smaller items

- `src/signet/chain.cljc` `extend-chain` comment: "The old proof is
  consumed and discarded" contradicts the README ("Extending leaves the
  old proof usable") — the old handle intentionally survives. Stale
  comment.
- `close` on a sendable (bytes-proof) token does not wipe the seed array,
  unlike `import-token!` which wipes its input array. The caller keeps a
  live bearer credential in a value they may think is dead.
- `export-token` requires the acknowledgement even for sealed or
  already-sendable tokens where nothing is exported — harmless but
  unnecessarily strict.
- Deprecated SSH path: `read-private-key`/`load-keypair` check that the
  three public-key copies agree but never check the seed derives to them
  (only `import-keypair!` does, via the vault). A corrupt file where
  seed‖pub disagree yields a keypair whose `:x` and `:d` don't match —
  signatures verify under a different key than the kid claims.
  Deprecated path, but the check is cheap.
- `adopt-session-entry!` (`src/signet/vault.cljc` ~L463-472) writes the
  `:session` row before `-adopt!`; if `-adopt!` throws, an orphan
  session-id entry is counted by `session-entry-count` but the provider
  lacks it. Swap the order.
- `consume!`/`destroy-quietly!` catch `Exception` only — a `Throwable`
  (e.g. `AssertionError`) mid-operation skips cleanup. Edge case.
- `read-message!`/`write-message!` with a non-bytes argument, or a
  non-bytes `:prologue`, throws raw `IllegalArgumentException` from
  `alength` rather than a typed error.
- `secp256k1` (`src/signet/impl/jvm_secp256k1.clj`): `detect-sig-format`
  classifies any 64-byte signature as raw, so a 64-byte DER signature
  (possible for small r,s from external signers) is misclassified and
  fails verification; `der->raw-sig` also never validates the outer
  SEQUENCE length. JCA verify is the backstop so this only rejects
  signatures that should pass — rare, but a note.
- `cli/verify` (`src/signet/cli/verify.clj`): a bare `--curve` with no
  value silently defaults to ed25519 instead of a usage error; `parse-args`
  accepts a trailing `--flag` with no value; `read-bytes` does not check
  short reads on `@file`.
- `unbox` `:from` expectation accepts only kid strings — passing a public
  key record silently resolves to no senders (`:unknown-sender`) rather
  than an error. Consider coercing via `key/kid`.
- `create-third-party-block` docstring claims "Pure for Ed25519" but a
  handle input reads the vault — impure.
- `noise_vectors_test`'s `fixed-ephemeral` imports via
  `vault/import-encryption-key!`, so the injected ephemeral's public key
  lands on the vault's public side (production ephemerals never do).
  Test-only, but it means the "ephemerals never on the public side"
  invariant isn't exercised under the vector harness.
- uuidv7 dependency is 0.7.2; 0.7.3 exists (CLI-only fixes — the library
  is unchanged, so this is cosmetic).
- `bb release-check` greps `"## X.Y.Z"` — an unreleased section header
  like `## 0.10.0 (unreleased)` already satisfies it, so a release could
  ship notes that still say "(unreleased)". Cosmetic.
- `chain/extend`'s error type `::no-default-signing-keypair` still says
  "keypair" though the default is now a vault key; it is a stable error
  contract, so renaming is a breaking change — just noting the drift.

## Things checked that are *not* problems

- Noise_KK implementation is spec-correct (token order, prologue-first
  MixHash, HKDF usage, nonce encoding) — confirmed by the passing
  cacophony and snow vectors on every backend.
- Nonce safety: box/seal use unique-per-message keys (random salt →
  HKDF), Noise uses monotonic counters inside single-use states, and the
  reuse tests + injection checks are real (I verified the race-test logic
  would actually catch a disabled `consume!`).
- `import-signing-key!`/`import-encryption-key!` wipe the caller's array;
  the `:memory` provider wipes lent copies; the `:sodium` provider keeps
  everything in guarded memory.
- `ssh/import-keypair!` is not broken by the import wipe — the seed→pub
  check uses `:x` (from the file), not the wiped `:d`.
- Key-store and defaults are race-safe (`swap-vals!` + CAS); ephemeral
  keys can't be registered; trust model (`valid` vs `verified`) is
  implemented consistently across sign/chain/box.
- CI is sound: backend matrix, checksum-pinned libsodium and bb, the
  dynamically-linked-bb assertion, release workflow verifies the tag
  against `build.clj` and smoke-tests the published jar.

## Suggested test additions

1. `unbox` by vault id with a shared key present (finding 1) — a few
   iterations, since the failure is ordering-dependent.
2. `(close sealed content)` → `::sealed` (finding 2).
3. `export-token` + `close` → proof gone (finding 3), whichever behaviour
   is chosen.
4. Malformed-point kids through `session/initiator`, `box`,
   `encryption-public-key` on both backends (finding 4) — ideally a
   parity check that asserts the *same* typed error.
5. `sign/verify` with a handle (finding 6).

---

## Resolution (0.9.4, 2026-09-26)

Verified by reproduction (findings 1–6 by REPL; finding 1 fails in about
half of all runs with fresh keys, 32/60 with the :to slot, 41/60
without). Every fix has a test in `test/signet/seams_test.clj` shown to
fail before it (13 tests: 38 failures and 1 error before).

| # | Result |
|---|---|
| 1 | Fixed: box/unbox use identity keys only; `vault/x25519-dh`, `vault/public-key` and `box` throw `:signet.vault/wrong-algorithm` for shared keys; new `vault/identity-key?`. |
| 2 | Fixed: `::sealed` in both arities. |
| 3 | Fixed: `close` of a sendable token destroys the vault's copy (every vault) and wipes the seed. |
| 4 | Fixed: JCA validates points exactly as libsodium (curve, small order, prime-order subgroup); both throw `:signet.impl/invalid-public-key` / `:signet.impl/low-order-point`. Parity check over 455 inputs (380 refused by both); removing the JCA subgroup check makes 162 disagree. |
| 5 | Fixed: `kid->public-key` uses `lookup`'s parser; `::malformed-kid`. |
| 6 | Fixed: `verify` accepts handles. |
| 7 | Fixed at `session/initiator`/`responder`, `shared-key!`, `register-public-key!` (`::bad-key-type`). |
| 8 | Fixed: `register!` throws `::no-kid`. |
| 9 | Fixed: 1..8160, `:signet.impl/bad-length`. |
| 10 | Fixed: vault errors pass through sessions unchanged. |
| 11 | Deferred to 0.10.0 (breaking for consumers that read the strings). |
| 12 | Deferred to 0.10.0. |
| 13 | Done: stale `extend-chain` comment, `close` wipes the sendable seed, `adopt-session-entry!` order, `create-third-party-block` docstring, `:from` accepts records and handles, CLI missing values, `release-check`, uuidv7 0.7.3. Not done: catching `Throwable` in cleanup, 64-byte DER signatures, the `export-token` acknowledgement for sealed tokens, the Noise-vector harness's ephemerals on the public side, the seed check in the deprecated SSH path (its JCA derivation fails on bb), the `::no-default-signing-keypair` name (a stable contract). |

## Re-verification (Devin, 0.10.0-SNAPSHOT @ 6fb9728)

Each claim above was re-checked empirically, not just read. All fixes
hold:

- **1:** 20/20 `unbox :default` calls succeed with a shared key in the
  vault (was ~50 % failing). Shared handle as `box` sender and
  `vault/public-key` on it → `:signet.vault/wrong-algorithm` ex-info.
- **2:** `(close sealed {:x 1})` → ex-data `{:type ::sealed}`, same as
  the 1-arity (was `ArrayStoreException`).
- **3:** `export-token` + `close`: seed array zeroed, vault copy gone
  (`vault/handle` → nil), extending the stale local token →
  `:signet.vault/destroyed-key` (was: key still signing).
- **4:** y=1 and random non-point inputs → `:signet.impl/invalid-public-key`
  on JCA (was `ArithmeticException`/garbage); low-order X25519 DH →
  `:signet.impl/low-order-point`. Parity run: 57 checks, 0 failed —
  455 inputs, 380 refused identically by both backends.
- **5:** `kid->public-key` on a 5-byte payload → `::malformed-kid`.
- **6:** `sign/verify` with a handle → true.
- **7:** secp256k1 kid and record as session peer → `::bad-key-type`;
  same for `shared-key!` and `register-public-key!` with non-keys.
- **8:** `register!` of a secp256k1 private-only key → `::no-kid`.
- **9:** `hkdf-sha-256` at 8160 ok, 8161 → `:signet.impl/bad-length`.
- **10/13:** verified in source/diff: vault errors pass through
  `open-aead`, `-adopt!` precedes the `:session` swap, CLI value checks,
  dated release-check heading, uuidv7 0.7.3, docstring fixes.

Suites: JCA 196 tests / 1055 assertions, sodium 196 / 1069 — 0 failures
(was 183/986, 183/1000; +13 seams tests). Deferred to 0.10.0 as stated:
11 (`chain/verify` string errors) and 12 (`verify-edn` `:type` check);
the remaining finding-13 minors are documented as intentionally not
done, with reasons. |
