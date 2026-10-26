# Tutorial: gaps and plan

The working list for what the tutorial finds. Coding is on hold (Frank,
2026-10-24): items are recorded and ordered here, decided with Frank, then
built in slices with the chapter's snippets as tests.

One task per line: `- [ ] **id** gap → proposal — references; status`.
Ticked means built or done. An unticked line is open unless it says
_decided_ or _agreed_.

## Found by chapter 1 (2026-10-24)

- [ ] **F1** `box` to a kid string throws a raw `IllegalArgumentException` (multimethod dispatch on nil), not an `ex-info` → accept kids in `box` (and everywhere a peer is named); wrong arguments give an `ex-info` naming the argument — D2
- [ ] **F2** unknown option keys are ignored: `{:ttl-ms …}` signs without expiry → reject unknown option keys — D13
- [ ] **F3** `box`/`unbox` take and return bytes (`.getBytes`, `String.`: JVM interop) while `sign-edn` takes EDN → `box`/`unbox` over EDN values; bytes as the lower layer — D14
- [ ] **F4** a box carries `:from`/`:to` kids in the clear by default → decide the default (visible vs hidden) — D14
- [ ] **F5** `:ttl` in seconds, `:expires`/`:now` in epoch ms → one convention — D13
- [ ] **F6** `generate-signing-key!` makes a key that also receives boxes and runs sessions → the identity reference — D1

## Found by chapter 3, key cards (2026-10-25)

- [ ] **C1** no card API: a card is made and read by hand (a map, `sign-edn`, `verify-edn`, a filter over `:keys`) → `signet.card`: `publish`, `read` (verify; check `:type`, `:v`, `:critical`; compute proof levels; apply the reader's rules) and `->assertions` — G13
- [ ] **C2** `verify-edn` accepts any signed map; nothing checks that it is a card → part of `card/read`
- [ ] **C3** deriving the agreement kid takes three calls in two namespaces → one function, e.g. `key/agreement-kid`
- [x] **C4** box to the derived X25519 kid works end to end (`unbox` finds the Ed25519 entry) → nothing to change — verified in the chapter
- [ ] **C5** one signer per envelope; a multi-key card is several envelopes → W5 (join on the message digest), later a multi-signer envelope
- [ ] **C6** validity as `:ttl` seconds → explicit `:not-before`/`:not-after` plus the reader's maximum — see F5
- [ ] **C7** no P-256 in signet, so the chapter's P-256 parts are fiction → G6

## From the design docs

- [ ] **G1** secp256k1 signing: no low-s normalization, no recovery id — docs/14
- [ ] **G2** signature profiles (`:x509`, `:cosmos`, `:eth`, …) as the extension of `-sign` — docs/14, D3
- [ ] **G3** two-signer envelopes for key bindings; `:same-entity` vs `:speaks-for`; transitivity — docs/14, D4
- [ ] **G4** vault files have several unlock entries but no key commitment — docs/13; N3's key id doubles as one
- [ ] **G5** seed derivation: expand-only HKDF-SHA-512 in nacljc (secret in, secret out; needs Frank's approval), a derive operation in signet's provider protocol — docs/15, D8
- [ ] **G6** P-256 library on bb (C library via FFI, or BouncyCastle through a JVM subprocess) — docs/14
- [ ] **G7** per-key capabilities (algorithm, profiles, operations, message limit, exportability, destroy semantics) — outline D5
- [ ] **G8** framed digest for providers with message limits (KMS 4096, agent 512) — docs/13, D6
- [ ] **G9** error taxonomy `:unsupported` / `:unavailable` / `:denied` / `:locked` — outline D11
- [ ] **G10** sync or async client API — outline D12
- [ ] **G11** `signet.chain`: require low-s before a chain root may be ECDSA — docs/14
- [ ] **G12** choosing algorithms and formats by the relying party: capability statements, matching keys from the seed — docs/14, D15
- [ ] **G13** a self-signed _key card_, an EDN map with `:type :signet/key-card`, exchanged instead of a bare kid: how keys, purposes, profiles and accepted formats reach a relying party (without it that knowledge is ad hoc and hard-coded). Subsumes G12's capability statement and G3's binding (signed by every key it names). Proof of possession only; trust is orthogonal — docs/14 "Key cards", D16; _decided_ 1–6 (2026-10-25; decision 3 revised to graded proof levels for `:agree` keys); dictionary and reader rules to finalize from chapter 3
- [ ] **G14** cards as says-statements in stroopwafel-pdp: self-scoped assertions admitted without trust, `:named` keeping its sayer, a join over multi-signed cards (`:message-digest`), a sayer for derived aliases; signet's `card->assertions` — docs/14 "How this maps onto stroopwafel"; detail in W1–W10
- [ ] **G15** box v3: an ephemeral sender key with static authentication (HPKE auth mode; X25519 and P-256 suites). Better than today's static-static box, but not forward-secret against compromise of the recipient's key; forward secrecy stays with Noise sessions or (later) one-time prekeys — docs/14 "Decisions", forward secrecy; _agreed_ (Frank, 2026-10-25), to build

## Stroopwafel and stroopwafel-pdp (G14 in detail, 2026-10-25)

Read: stroopwafel 0.11.0, stroopwafel-pdp's `spki` namespaces, and the
`:self` sketch in `stroopwafel-tutorial/notebooks/00_new_model_sketch.clj`.
Changes in those repos need Frank's approval, with a failing-first test
for each item and an injection check for each guard.

- [x] **W1** (stroopwafel) the fixpoint limit failed open: rule evaluation stopped silently at 100 iterations or 1000 facts, so missing derived facts made `:reject` checks and `:deny` policies pass (reproduced 2026-10-25: transitive closure over 50 edges allowed, over 40 denied) → fail closed at a limit (`{:valid? false}` plus a reason), limits configurable — built: stroopwafel 0.12.0 `270d2c2` (failing-first tests, injection-checked guards; not yet tagged or on Clojars); pdp `1ceccb1` passes `:error` and `:limits` through and depends on 0.12.0
- [ ] **W2** (pdp) injected and derived facts have no sayer (generic-assertion-schema open question 4); `[:named ?key ?name]` drops the sayer → `:self` as the sayer of injected and derived facts, as in the tutorial sketch: the local PDP, the only axiom `[:trusted :self]`, trust roots as `:self` assertions. One name predicate, `[:named-by ?sayer ?key ?name]` (SDSI `(K N)`); the local namespace is `[:named-by :self …]`, derived from K's bindings when `:self` trusts K for names. Guard: a sayer always comes from signature verification, never from a message, so no signed input can claim `:self` (injection test) — _decided_ `:self` (Frank, 2026-10-25)
- [ ] **W3** (pdp) statements from untrusted sayers are dropped (pre-filter pass 4), so a key card's statements vanish → **trust as facts, activation by rules** (Frank, 2026-10-25): every verified statement enters the store with its sayer and stays dormant until a trust fact (`:self` trusts K for a type, scope and period) activates it. Delegation closure becomes recursive rules. "A key may speak about itself" is a default `:self` rule (subject = sayer). A statement naming another key (`:same-entity`) counts only with that key's signature; "K2 speaks for K1" is self-scoped for K1, "K1 speaks for K2" is not. Validity is the intersection of the statement's, the trust fact's and each delegation step's (the logic now in pdp `trust.clj`)
- [ ] **W3a** (stroopwafel, pdp) dormant raw facts must not be visible to policies (a policy matching a raw tuple bypasses trust) → a discipline (policies read only activated predicates, enforced by a check on the policy set) or an engine feature (an origin rules can lift from but policies can't see; today the authorizer's rules and policies share one scope)
- [ ] **W3b** (pdp) volume: anyone can submit statements → per-sayer caps or a relevance filter in the pre-filter; depends on W1 (bypass without it, denial of service with it)
- [ ] **W4** (pdp) revocation and negative permissions → revocation stays a **pre-filter**, applied before the reduction, with **revocation authority that is never derived**: (1) a sayer may always revoke its own statements; (2) `:self`; (3) revokers `:self` configures. No revocation through delegation, so no cycle with trust in Datalog and no negation in rules. Prefer short validity and positive freshness (a recent "still valid as of t" statement). Negatives only as `:self`'s deny policies or attenuating checks, never as statements from others. Fail closed when a revocation source is unavailable — docs/14 "Revocation and negatives"; _decided_ pre-filter (Frank, 2026-10-25)
- [ ] **W5** (pdp, signet) one signer per block; a card is signed by every key it names → N envelopes over the same card, joined on `:message-digest` (or the assertion `:id`s): `[:card-signed-by digest kid]`; semantically identical to multi-sig when the reduction requires every signer. A multi-signer envelope in signet later, as an optimization: one object, one id for revocation, k-of-n thresholds (Frank likes it)
- [ ] **W6** (signet) cards to facts → `card->assertions`: deterministic, plain data, no dependency on stroopwafel
- [x] **W7** (stroopwafel) docs described the pre-0.11 token API → README and `context.md` rewritten on 2026-10-25; the use-case, LLM and websocket docs marked as pre-0.11
- [ ] **W8** (signet, stroopwafel) one fact db for keys, capabilities and cards (Frank, 2026-10-25) → holdings, state and received facts in one db; a card is a query over holdings; statecharts per provider write state facts. **Only references to secrets in the db** (_decided_, Frank 2026-10-25): a guard rejects secret material as a fact value (failing-first test, injection check); AWS credentials, PIN, bearer tokens and derived secrets stay vault entries, facts name their handles. Metadata privacy: the persisted db encrypted at rest (vault file), core dumps off, a logging policy for explain output and fact dumps, optionally a signed configuration for `:self` facts — docs/14 "One fact db", "Secrets and metadata"
- [ ] **W9** (stroopwafel) no generic query API: the engine is shaped around tokens, origins are block indices → store, rules, query, sayers as origins; returns binding maps; used by token evaluation and signet; `.cljc` port — docs/14 "Stroopwafel inside signet"
- [ ] **W10** (stroopwafel) no aggregation; solution order is arbitrary → grouping and ordering after the query (Frank): declarative post-processing on the result maps (sort, group, min/max, count, first); deduplicate by projection, total order with a tie-breaker, ranks from rank facts; never rely on solution order — docs/14 "Grouping and ordering after the query"

## Sessions, key ids and local names (brainstorm, 2026-10-25)

docs/14 "Sessions, key ids and local names".

- [ ] **N1** sessions have no public id; `h` is internal to `session.cljc` (verified) → a `session-id` accessor returning the handshake hash `h`, only after the handshake
- [ ] **N2** no rekey; one key per session → epochs: `(session-id, epoch n)`; a symmetric ratchet (Noise `Rekey()`) first, a DH ratchet as a later option
- [ ] **N3** symmetric keys have no id → `key-id = BLAKE2b(key = k, "signet/key-id/v1")` as a provider operation; high-entropy keys only; doubles as the key commitment G4 asks for
- [ ] **N4** sessions are named only by the objects that hold them → local session ids per side, QUIC-style: the receiver's id on the wire, rotatable; `h` and the epoch inside the associated data
- [ ] **N5** peers are named by kid only → petnames bound to principals (`[:named-by :self kid "bob"]`, W2), never to one key; the operation picks the facet; explicit adoption of card nicknames; uniqueness enforced, fail closed
- [ ] **N6** `box` needs a handle, a public-key record and bytes → `(box "alice" msg)`: default identity, petname → card → capability matching (W10), EDN payload (D14); the choice returned and pinnable; specific errors; a tutorial `[new]` snippet. Later a `send` over session or box

## Distribution and discovery (brainstorm, 2026-10-26)

docs/14 "Distribution and discovery of cards".

- [ ] **K1** no way to share cards among peers → a grow-only set of signed card bytes keyed by digest, one single-writer chain per identity; current card decided by `card/read` (`:supersedes`, `:next`, validity), never by a CRDT; Yjs only where all writers trust each other (its threat model §3.1)
- [ ] **K2** reader defenses for a set of cards → size checks before parsing, CEDN depth limits, caps per sayer (W3b); fork detection (two cards superseding one) fails closed; hash fetched bytes against their digest; prune superseded cards but keep chain tips and fork evidence
- [ ] **K3** no lookup by key → directory index under signing and derived keys only (never asserted keys); the reader verifies every answer
- [ ] **K4** no lookup by name → name bindings as a namer's signed statements (`[:named-by ns "bob" kid]`) stored in the same untrusted directory; trust in the namer is a `:self` fact
- [ ] **K5** no directory → the Datomic model: one ordering transactor, signed hash-chained transactions, `since t` sync, subscriptions, the local fact db (W8) as the peer's db; a bb HTTP service or static files first; DHT (BEP 44, Pkarr) or Nostr relays as later backends
- [ ] **K6** a directory can withhold, roll back or equivocate → transparency: Merkle tree over the log (inclusion and consistency proofs), witnesses comparing signed tree heads; a verifiable map for partial replication; short validity and several directories meanwhile

## Order (proposed)

1. Done: **W1** (the engine fails closed at its limits; stroopwafel 0.12.0, pdp `1ceccb1`). **Key card** (G13, D16): decisions 1–6 made, chapter 3 drafted (C1–C7). Profiles (G2), capabilities (G7), bindings (G3) and relying-party choice (G12) take their vocabulary from it.
2. Chapters 2 and 6 against today's API (more F-items expected).
3. Chapters 4, 5 and 7 as design fiction: forces D1–D9 and D15.
4. Decisions with Frank, in this order: D1 (identity), D2 + D13 + D14 (small, chapter-1 fixes), D3/D5 (profiles, capabilities), D15, D8/D9 (seed), the rest.
5. First code slice: F1, F2, F5 (small, local), each with a failing-first test.

## Open questions

- Chapter 3: does "using several keys by purpose" (`(sign me tx {:for :cosmos})`) stay in chapter 3 or move to chapter 4?
- W1: which signet version should stroopwafel-pdp's `deps.edn` use (0.3.1 can't be resolved)? Tag and deploy stroopwafel 0.12.0 to Clojars?
- W8: do cards publish holdings only, never state? A backup `:agree` key on another provider in the default card, for a lost YubiKey? Does the db live inside signet or in an identity layer next to it?
- N5: the form of a petname: string, keyword or tagged?
- N2: a DH ratchet, or the symmetric ratchet only?
- K3: index cards under signing and derived keys only?
- K5: first directory as a bb HTTP service with subscriptions, or static files over HTTPS? Full replication first, verifiable map later? `signet.chain` as the log format?
