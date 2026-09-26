# Sessions on vault handles: implementation plan (0.9.0)

Status: DRAFT plan, 2026-09-24. Implements decision 9 of
`docs/07-secret-handles-design.md` ("a secret derived from a vault secret
stays in the vault"). Decision 17 (deprecating key records) follows as a
separate step at the end.

## Where we are

`signet.session` keeps every secret as a byte array in the state map:

| Secret | Field | Lifetime today |
|---|---|---|
| local static private key | `:local-static-kp` `:d` (a key record) | caller's |
| local ephemeral private key | `:local-ephemeral-kp` `:d` | wiped at `split!` |
| DH outputs (es, ss, ee, se) | none (passed straight to `mix-key!`) | wiped in `mix-key!` |
| chaining key `ck`, handshake key `k` | `:ck`, `:k` | wiped at `split!` |
| transport keys | `:send :k`, `:recv :k` | never wiped |

The gaps:

- Session secrets live on the Clojure heap even under the `:sodium`
  provider.
- The `ck`/`k` pairs that each `mix-key!` replaces are never wiped. They
  can't be wiped early, because a failed read has to leave the old state
  usable.
- Transport keys are never wiped, and there is no way to end a session.
- A state prints its secrets.
- The local static key must be a key record, which is the type decision 17
  deprecates.

## Target

- **Secrets:** a state holds no secret bytes. `ck`, `k`, both transport
  keys and the local ephemeral are vault handles. They live in the vault
  of the local static handle, or in `:vault` from opts when a deprecated
  key record is passed.
- **What stays in the state:** only public values: `h`, public keys,
  counters, the phase and the single-use marker. Printing or logging a
  state leaks nothing.
- **Lifecycle:** the vault holds exactly the secrets of the live states.
  A successful `write-message!`/`read-message!` destroys the entries only
  the consumed state used. A failed or losing call destroys the entries
  it created. `close!` ends a session: it destroys every entry the
  session ever created, from any of its states. `with-conclave` calls it
  automatically when a block exits.
- **Wire format:** unchanged, checked byte for byte by known-answer
  vectors on both backends.
- **API** (the static key is an identity, so it comes as a handle):

  ```clojure
  (session/initiator my-handle their-public-or-kid)
  (session/initiator my-handle their-public-or-kid {:prologue bs})
  (session/responder my-handle their-public-or-kid)
  (session/write-message! st pt)  (session/read-message! st ct)   ; unchanged
  (session/established? st)                                       ; unchanged
  (session/close! st)   ; new: destroys all the session's secrets, from any of its states
  (session/with-conclave [st (session/initiator my-handle peer)]   ; new: close! on exit
    ...)
  ```

  A peer kid is resolved with `vault/lookup`, as in `shared/shared-key!`.
  Key-record arguments still work in 0.9.0, marked deprecated.

## Phase 0: known-answer vectors on today's code (safety net)

**Done (2026-09-25).** `test/signet/noise_vectors_test.clj` checks every
message against the cacophony and snow `Noise_KK_25519_ChaChaPoly_SHA256`
vectors. It found a bug: signet mixed the prologue into the transcript
hash after the static keys instead of before (Noise §5.3), so its
handshake messages matched no other implementation. Fixed; this breaks
handshakes with 0.8.0 peers (CHANGELOG 0.9.0). With the order swapped
back, 5 of the 26 assertions fail.

Before anything moves, pin the wire format.

1. Inject fixed ephemerals in the test with `with-redefs` on the private
   `fresh-ephemeral`, so production code gets no injection hook. Phase 3
   keeps a single ephemeral-creating function as that seam.
2. Add a known-answer test for `Noise_KK_25519_ChaChaPoly_SHA256`. Use the
   cacophony/snow vectors if they cover KK with this suite (to confirm);
   otherwise record vectors from today's code and cross-check them once
   against an independent implementation. Each vector checks every
   handshake and transport message.
3. Run it on `:jca` and `:sodium` (JVM and bb). Both backends meeting
   the same published vectors covers session parity, so
   `backend_parity.clj` needs no session case.

This is a separate commit. Everything after it has to keep these vectors
green.

## Phase 1: nacljc 0.3.0 (prerequisite for `:sodium`)

**Implemented in `../nacljc` (2026-09-25), not released.** Both changes are
tested on bb, the JVM and nbb, with each guard shown to fail when removed.
Release when signet's phases 2–3 have used the API.

Noise's MixKey is `HKDF(salt = ck, ikm = dh)`, and Split is
`HKDF(salt = ck, ikm = "")`. In both, the **salt is the secret**. nacljc's
`hkdf-sha-256` accepts a secret only as `ikm` (`check-optional-bytes` on
salt), and whether the output is a secret follows `ikm` alone. So under
`:sodium` the chaining key would have to leave guarded memory.

Changes:

1. `hkdf-sha-256`: accept a secret salt. The output is a secret if `ikm`
   or `salt` is one. Split's empty `ikm` with a secret `ck` must give a
   secret.
2. `secret-split`: new secrets holding consecutive parts of a secret, for
   example `(secret-split s [32 32])` gives `[s1 s2]`. It copies inside
   guarded memory and leaves `s` unchanged (the caller destroys it). Noise
   always needs two 32-byte outputs from one 64-byte HKDF, and T(2)
   depends on T(1), so two separate calls can't produce them.
3. Tests, release to Clojars, then bump nacljc in signet's `deps.edn`
   `:sodium` alias and in `bb.edn`'s `test:bb-sodium` and `test:jar`
   (their versions must match).

The `:memory`/JCA path needs none of this.

## Phase 2: vault support for session secrets

**Done (2026-09-25)**, on branch `sessions-on-handles` (which uses
`../nacljc` through `:local/root` until nacljc 0.3.0 is released). Two
changes from the text below:

- An ephemeral's id is its public key's kid, not a random id. The public
  key goes over the wire in the clear anyway, and this lets the vault use
  the provider's existing `-generate!`. Derived entries (`ck`, `k`,
  transport keys) do get random ids.
- `hkdf-pair!` splits the 64-byte output with a new backend function,
  `impl/split-material` (bytes under JCA, `nacljc/secret-split` under
  libsodium). The facade now has 18 functions.

Found while testing: the `:sodium` provider's `-adopt!` stored byte
material as it was, so destroying it failed. It now moves bytes into
guarded memory with `secret-import!`, so a `:sodium` vault holds only
secrets.

These are internal, `^:no-doc` functions, called only by `signet.session`.

**Session entries.** Session secrets are secret-side entries of a separate
kind:

- They never go on the public side.
- They never appear in `handles`.
- They can never be a default.
- They are never exported: `export-secret` refuses them with
  `::not-exportable`.

Their ids are random (`urn:signet:session:<random>`), never derived from
the key, in the spirit of decision 16. An ephemeral's id is also random,
not its public key's kid. The vault records the kind in a new `:session`
map, next to `:shared`: entry id → the id of the session that created
it. `unregister-vault!` and `destroy!` already cover them.

**Operations**, each written with `-with-material`/`-adopt!` so the
`Provider` protocol doesn't change:

| Function | Does |
|---|---|
| `generate-ephemeral!` `[vault-id]` | New X25519 key in the provider, returns `[h pub-bytes]`. Under `:sodium` it is born in guarded memory. |
| `x25519-dh` `[h their-pub]` | Exists already. Also accepts ephemeral handles. Output is material the caller must destroy. |
| `hkdf-pair!` `[vault-id salt ikm]` | Noise HKDF: two 32-byte outputs as two new session handles. `salt` is public bytes (the initial `ck`) or a handle. Destroys `ikm`. |
| `aead-encrypt` / `aead-decrypt` `[h nonce pt aad]` | ChaCha20-Poly1305 under a handle key. |
| `destroy-session!` `[vault-id session-id]` | Destroys every entry tagged with session-id. Idempotent. |
| `session-entry-count` `[vault-id]` | How many session entries the vault holds. For monitoring abandoned sessions, and for the accounting tests. |

`generate-ephemeral!` and `hkdf-pair!` take the session id and tag each
new entry with it.

Tests go in `vault_test.clj`: session entries are invisible to `handles`
and `lookup`, can't be exported, and outputs match `impl` for the same
inputs on both providers.

Later, when a remote enclave (agent, HSM) arrives, these operations become
provider protocol methods so the keys never leave the enclave. That is not
needed now.

## Phase 3: the session refactor

**Done (2026-09-25), with phase 4,** on branch `sessions-on-handles`. The
Noise vectors pass unchanged, with handles and with key records, on JCA,
on libsodium on the JVM, and on bb. Details that differ from the steps
below:

- State keys are renamed: `:local-static`, `:local-ephemeral` (an
  `EphemeralKeyPair` with `:handle`, no `:d`).
- Tracking uses a private dynamic var, `*created*`, bound by `consume!`,
  instead of passing a collector through every helper.
- The winner's cleanup destroys quietly. A racing loser may still be
  inside a call on the same secret (libsodium then refuses to free it
  with `::secret-in-use`); such an entry stays until `close!`.
- A loser whose op fails because the winner destroyed what it was using
  gets `::stale-session-state`, not `::destroyed-key`.
- The session id is `(random-uuid)`.
- A local static handle must be one its vault holds as an identity
  (`vault/handle` returns it, so not a session entry) with algorithm
  `:ed25519` or `:x25519`; otherwise `::no-private-key`. A peer given as
  a kid that can't be resolved throws `::unknown-peer`.
- `with-conclave` gets a clj-kondo `lint-as` in the project config and in
  `src/clj-kondo.exports/com.github.franks42/signet/config.edn`, for
  consumers.

1. **State shape:**

   ```clojure
   {:phase :handshake :role :initiator :pos 0 :consumed <marker>
    :vault :default
    :session-id <random> :closed <atom>       ; shared by every state of the session
    :h <bytes> :ck <bytes-or-handle> :k <handle-or-nil> :n 0
    :local-static <handle-or-record>          ; the caller's, never destroyed
    :remote-static-pub <pub record>
    :local-ephemeral <EphemeralKeyPair :x pub :h handle>
    :remote-ephemeral-pub <EphemeralPublicKey>}
   ;; after Split:
   {:phase :transport :role … :vault … :consumed … :session-id … :closed …
    :send {:k <handle> :n 0} :recv {:k <handle> :n 0}}
   ```

   The initial `ck` is the public protocol-name hash, so nothing enters
   the vault before the first message. `initiator` and `responder` draw a
   random session id and create the `:closed` atom. Under the naming
   convention that is a read of the random generator, so they keep their
   names without `!`, and their docstrings get an `Impure:` line.

2. **dh/edh stay enforced.** `EphemeralKeyPair` keeps its own type and now
   carries a handle (`:h`) instead of `:d`. `dh` and `edh` check the record
   types exactly as today. The local static goes through one dispatch:
   `vault/x25519-dh` for a handle, `impl/x25519-dh` for a deprecated
   record.

3. **mix-key!** becomes a call to `hkdf-pair!`. The DH output is destroyed
   inside that call.

4. **Split** runs `hkdf-pair!` with an empty `ikm` and the `ck` handle,
   producing the transport handles.

5. **Tracking in consume!** `consume!` gives the op a collector (a
   `volatile!`) that every helper creating a vault entry adds to. Then:
   - **the op throws** (a forged message, for instance): destroy every
     entry it created and rethrow. The state is not consumed, as today.
   - **the op succeeds but loses the compare-and-set:** destroy every
     entry it created, then throw `::stale-session-state`.
   - **the op succeeds and wins:** destroy the entries it created that the
     next state doesn't hold (intermediate `ck`/`k` from es-then-ss), plus
     the entries the consumed state held that the next state doesn't hold.
     This is where a replaced `ck`/`k` and the ephemeral at Split get
     destroyed.

   The local static handle is never tracked and never destroyed.

6. **Closing by session, not by state.** A state is replaced with every
   message, so the state a caller still holds, for example the one bound
   at the top of a block, is usually a consumed one. That's why `close!`
   works from **any** state of a session: the first one, a consumed one,
   or one from before an exception. It does two things:
   - sets the session's shared `:closed` atom. `consume!` checks it first,
     so any state of a closed session throws `::session-closed`, which is
     clearer than `::destroyed-key` coming from the vault;
   - calls `vault/destroy-session!` with the session id.

   Closing twice is a no-op. The per-step cleanup in step 5 still destroys
   replaced `ck`/`k` and the ephemeral right away, for forward secrecy
   during the handshake. Closing by session is the backstop: an entry
   that step 5 misses (a bug, a dropped state) stays until the session is
   closed, not for the rest of the process.

7. **`with-conclave`**, a macro in the style of `with-open`:

   ```clojure
   (session/with-conclave [s (session/initiator my-h peer-kid)]
     (let [[s msg1] (session/write-message! s payload)
           ...]
       ...))
   ;; expands to
   (let [s (session/initiator my-h peer-kid)]
     (try ... (finally (session/close! s))))
   ```

   The body keeps threading states as usual. `close!` on the state bound
   at the top closes the whole session, even when the body threw after
   several messages. Docstring caveats:
   - A state or a lazy seq that escapes the block and is used later throws
     `::session-closed` (the usual `with-open` rule).
   - It fits sessions whose lifetime is one block: a request, or a
     connection handler that is one function call. A long-lived session,
     such as one kept in a connection registry, needs an explicit `close!`
     wired to the connection's close.
   - There is no cleanup on garbage collection. `java.lang.ref.Cleaner`
     may not exist on babashka and would fire long after the key should
     have gone.

   **Who calls what.** Today nothing in signet or its sibling projects
   sits above `signet.session`: the application calls it directly, so
   `with-conclave` and `close!` are part of the API it sees. They become
   invisible once a layer that owns the connection drives the session:
   - a layer that runs a whole session in one call (handshake, request,
     reply) wraps its body in `with-conclave`;
   - a layer with long-lived connections (sockets, websockets,
     core.async) calls `close!` when the connection closes, because no
     lexical block spans the session.

   In both cases the caller of that layer never deals with cleanup. Such
   a transport layer is out of scope for signet (a crypto library); it
   belongs to a consumer or a companion library. The `with-conclave`
   docstring states this division, and the README session section shows
   both patterns.

8. **Docstrings** follow the naming convention. The ns docstring no longer
   claims "no atoms, no global state". `write-message!`/`read-message!`
   get `Impure:` lines that name the vault. `::not-a-session-state` stays
   for maps without a marker.

## Phase 4: tests

**Done (2026-09-25).** `session_test.clj` runs on handles, with one
deprecated-record test, plus lifecycle tests:
- entry counts after each step;
- a failed read leaves nothing behind;
- no secret bytes in any state;
- replaced secrets are destroyed;
- `close!` from the first state;
- `with-conclave` on normal exit and on an exception;
- two independent sessions in one vault.

`trust_test.clj` checks that ephemerals are destroyed in the vault, and
has a new race test for handshake writes. Removing any one of seven guards
(winner cleanup, failed-op cleanup, loser cleanup, close by session, the
closed flag, single-use CAS, the local-handle check) fails at least one
test.

The existing tests are adapted to take handles; each keeps one
deprecated-record case. The known-answer vectors from phase 0 must pass
unchanged on both backends.

New tests:

- **Accounting invariant:** after each step (msg1, msg2, transport,
  failed read, a lost race from `concurrent-writes-from-one-state…`, and
  `close!`), the number of session entries in the vault equals what the
  live states hold: 0 before msg1, 2 per side for `ck`/`k` plus 1 for the
  initiator's ephemeral during the handshake, 2 per side after Split, and
  0 after `close!`. The count comes from `vault/session-entry-count`.
- **Closing:**
  - `close!` from the *first* state, after a full handshake and some
    transport messages, leaves 0 entries;
  - `close!` twice is a no-op;
  - any state of a closed session throws `::session-closed`, both from
    `write-message!` and `read-message!`;
  - an exception inside `with-conclave` after several messages still
    leaves 0 entries and rethrows the original exception;
  - two concurrent sessions in one vault: closing one leaves the other
    working.
- **No secrets in state:** a structural walk finds no byte array other
  than `h` and public keys, and `pr-str` of a state is safe. This is the
  same style of check as "no byte array in ex-data".
- **Stale handles are gone:** the consumed state's `ck` handle throws
  `::destroyed-key` when used through the vault.
- **Trust tests:**
  - `session-ephemerals-dropped-and-zeroed` becomes "the ephemeral's
    vault entry is destroyed at Split".
  - `session-ephemerals-never-registered` extends to the vault's public
    side and to `handles`.
- **Injection checks,** in the style of the existing ones:
  - disabling the destroy step in `consume!` must fail the invariant test;
  - making `close!` destroy only the given state's entries (not the
    session's) must fail the close-from-the-first-state test;
  - putting a byte array back into the state must fail the no-secrets
    test.

Suites: `bb test:all` (jca, jvm-sodium with parity, bb-sodium) and
`bb test:jar`.

## Phase 5: docs

- `docs/05-noise-kk-session-design.md`: the state shape and the
  lifecycle.
- `docs/07`: mark sessions done, and fix the stale release-plan line
  ("in 0.7.0 or next (open)").
- README session example with handles.
- CHANGELOG 0.9.0: new `close!` and `with-conclave`, record arities
  deprecated, the nacljc bump.
- README and `docs/05`: sessions must be closed, with `with-conclave` or
  an explicit `close!`, or their secrets stay in the vault.
- CLAUDE.md: session section, test counts.

## Phase 6: deprecate key records (decision 17)

Separate commits, same release:

- Add `^:deprecated "0.9.0"` and a docstring pointer to the vault
  equivalent on the key-record constructors and `!` twins, and on the
  session record arities.
- SSH import gets a vault path, for example `ssh/import-keypair!`,
  returning a handle (it goes through `import-signing-key!`, which wipes
  the parsed seed).
- Nothing is removed.
- Consider batching the 2026-09-23 naming-inventory renames into this
  release, so the breaking changes all land together.

## Decisions (2026-09-24/25)

1. **Ephemerals live in the vault** (settled). The state then holds no
   secrets, and under `:sodium` ephemerals are born in guarded memory.
   "Ephemerals are never registered" is restated as "never on the public
   side, never in `handles`, destroyed at Split", and trust_test changes
   accordingly.
2. **Record arities stay in 0.9.0, deprecated** (settled).
3. **Abandoned sessions** (settled): document that sessions must be
   closed; `close!` closes a whole session from any of its states; the
   `with-conclave` macro closes on exit; `vault/session-entry-count` lets
   callers monitor what's left. No cleanup on garbage collection. Under
   `:sodium` each entry is guarded memory (pages plus guard pages,
   counted against mlock limits), which is why this matters.
4. **Rekey** (Noise `REKEY`) and the 2^64 nonce limit: out of scope for
   now (settled). Not designed yet; to be discussed separately.
5. **The macro is `with-conclave`** (settled 2026-09-25). A conclave is a
   closed meeting, from the Latin *con clave*, "with a key": a room locked
   with a key. That is a session whose keys live in the vault and are
   destroyed when it ends. The docstring states the name's meaning and
   that a conclave is not an enclave (where a vault's secrets live,
   docs/07 decision 8). Rejected:
   - `with-session`: "session" is used everywhere.
   - `with-vault-session`: would collide with a later "vault session" (the
     time a vault is unlocked).
   - `with-enclave`: "enclave" already names where providers keep secrets
     in docs/07, and in the industry (SGX, Apple's Secure Enclave). Keep it
     free for a future block that runs against a given enclave.
   - `with-parley`, `with-confab`, `with-closing-session`: considered;
     `with-conclave` conveys a private, locked meeting best.

## After 0.9.0: password unlocking (crypto_pwhash)

Recorded 2026-09-25; it belongs to "persistence and password unlocking"
in docs/07.

- **nacljc** binds `crypto_pwhash` (Argon2id). Its output is a key, and
  it should be a secret whenever the password is passed in as one.
  `crypto_pwhash_str`/`_str_verify` are for storing login passwords
  (server side). Key unlocking doesn't need them: the AEAD tag already
  shows a wrong password, and a stored verifier would only give an
  attacker a second target for offline guessing.
- **Two layers of keys.** A random vault master key encrypts the stored
  secrets. The password-derived key (Argon2id, random salt) encrypts only
  the master key. So:
  - changing the password rewraps one key;
  - other unlock methods (OS keychain, hardware key, recovery code) can
    each wrap their own copy of the master key.
- **Header:** a suite id, the salt and the Argon2id cost settings
  (`opslimit`, `memlimit`), authenticated as associated data (docs/07
  "suites, not knobs"). Costs can then rise later without breaking old
  files, and can't be quietly swapped for cheaper ones.
- **Unlocked** means the master key is in guarded memory; **locking**
  destroys it.
- **Caveats:**
  - Argon2id only makes each guess expensive: a weak password stays weak.
  - A password arrives as a Clojure string and can't be wiped reliably.
  - High memory settings are slow in the browser (WebAssembly).
- **Not in libsodium:** BLAKE3. It has BLAKE2b (`crypto_generichash`),
  SHA-2, SHA-3 and SHAKE/TurboSHAKE.

## Order and size

1. Phase 0 (commit).
2. nacljc 0.3.0 (its own repo and release).
3. Phase 2 (commit).
4. Phases 3 and 4 together (the main change).
5. Phase 5.
6. Phase 6.

Phases 3–4 are the bulk: roughly 250 changed lines in `session.cljc`,
about 80 in `vault.cljc`, and the test updates.
