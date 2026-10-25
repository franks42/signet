# Tutorial: gaps and plan

The working list for what the tutorial finds. Coding is on hold (Frank,
2026-10-24): items are recorded and ordered here, decided with Frank, then
built in slices with the chapter's snippets as tests. Status: **open**,
**decided**, **built**.

## Found by chapter 1 (2026-10-24)

| # | Gap | Proposal | Decision | Status |
|---|---|---|---|---|
| F1 | `box` to a kid string throws a raw `IllegalArgumentException` (multimethod dispatch on nil), not an `ex-info` | accept kids in `box` (and everywhere a peer is named); wrong arguments give an `ex-info` naming the argument | D2 | open |
| F2 | unknown option keys are ignored: `{:ttl-ms …}` signs without expiry | reject unknown option keys | D13 | open |
| F3 | `box`/`unbox` take and return bytes (`.getBytes`, `String.`: JVM interop) while `sign-edn` takes EDN | `box`/`unbox` over EDN values; bytes as the lower layer | D14 | open |
| F4 | a box carries `:from`/`:to` kids in the clear by default | decide the default (visible vs hidden) | D14 | open |
| F5 | `:ttl` in seconds, `:expires`/`:now` in epoch ms | one convention | D13 | open |
| F6 | `generate-signing-key!` makes a key that also receives boxes and runs sessions | the identity reference | D1 | open |

## From the design docs

| # | Gap | Where | Status |
|---|---|---|---|
| G1 | secp256k1 signing: no low-s normalization, no recovery id | docs/14 | open |
| G2 | signature profiles (`:x509`, `:cosmos`, `:eth`, …) as the extension of `-sign` | docs/14, D3 | open |
| G3 | two-signer envelopes for key bindings; `:same-entity` vs `:speaks-for`; transitivity | docs/14, D4 | open |
| G4 | vault files have several unlock entries but no key commitment | docs/13 | open |
| G5 | seed derivation: expand-only HKDF-SHA-512 in nacljc (secret in, secret out; needs Frank's approval), a derive operation in signet's provider protocol | docs/15, D8 | open |
| G6 | P-256 library on bb (C library via FFI, or BouncyCastle through a JVM subprocess) | docs/14 | open |
| G7 | per-key capabilities (algorithm, profiles, operations, message limit, exportability, destroy semantics) | outline D5 | open |
| G8 | framed digest for providers with message limits (KMS 4096, agent 512) | docs/13, D6 | open |
| G9 | error taxonomy `:unsupported` / `:unavailable` / `:denied` / `:locked` | outline D11 | open |
| G10 | sync or async client API | outline D12 | open |
| G11 | `signet.chain`: require low-s before a chain root may be ECDSA | docs/14 | open |
| G12 | choosing algorithms and formats by the relying party: capability statements, matching keys from the seed | docs/14, D15 | open |
| G13 | **next to resolve** (Frank, 2026-10-25): a self-signed *key card*, an EDN map with `:type :signet/key-card`, exchanged instead of a bare kid. It is how keys, purposes, profiles and accepted formats reach a relying party; without it that knowledge is ad hoc and hard-coded. It subsumes G12's capability statement and G3's binding (signed by every key it names). Proof of possession only; trust is orthogonal | docs/14 "Key cards", D16 | decided 1–6 (2026-10-25; decision 3 revised to graded proof levels for `:agree` keys); dictionary and reader rules to finalize in the card chapter |
| G15 | box v3: an ephemeral sender key with static authentication (HPKE auth mode; X25519 and P-256 suites). Better than today's static-static box, but not forward-secret against compromise of the recipient's key; forward secrecy stays with Noise sessions or (later) one-time prekeys | docs/14 "Decisions", forward secrecy | agreed (Frank, 2026-10-25), to build |
| G14 | cards as says-statements in stroopwafel-pdp: self-scoped assertions admitted without trust, `:named` keeping its sayer, a join over multi-signed cards (`:message-digest`), a sayer for derived aliases; signet's `card->assertions` | docs/14 "How this maps onto stroopwafel" | open |

## Stroopwafel and stroopwafel-pdp (G14 in detail, 2026-10-25)

Read: stroopwafel 0.11.0, stroopwafel-pdp's `spki` namespaces, and the
`:self` sketch in `stroopwafel-tutorial/notebooks/00_new_model_sketch.clj`.
Changes in those repos need Frank's approval, with a failing-first test
for each item and an injection check for each guard.

| # | Gap | Proposal | Repo | Status |
|---|---|---|---|---|
| W1 | **The fixpoint limit fails open.** Rule evaluation stops silently at 100 iterations or 1000 facts. Missing derived facts make `:reject` checks and `:deny` policies pass. Reproduced on 2026-10-25: transitive closure over 50 edges allowed, over 40 it denied. | fail closed when a limit is reached (`{:valid? false}` plus a reason); make the limits configurable. Changes the expectation of the existing test `fact-explosion-capped` on purpose | stroopwafel | **built**: stroopwafel 0.12.0, `270d2c2` (2026-10-25), with failing-first tests and injection-checked guards. Not yet on Clojars or tagged. stroopwafel-pdp passes `:error` and `:limits` through and depends on 0.12.0 (pdp `1ceccb1`). Open: the pdp's default `deps.edn` asks for signet 0.3.1, which can't be resolved (it was already like that); which signet version to use is Frank's choice |
| W2 | injected and derived facts have no sayer (generic-assertion-schema open question 4); `[:named ?key ?name]` drops the sayer | `:self` as the sayer of injected and derived facts, as in the tutorial sketch: the local PDP, the only axiom `[:trusted :self]`, trust roots as `:self` assertions. One name predicate, `[:named-by ?sayer ?key ?name]` (SDSI `(K N)`). The local namespace is `[:named-by :self …]`, derived from K's bindings when `:self` trusts K for names. Guard: a sayer always comes from signature verification and never from a message, so no signed input can claim `:self` (injection test) | pdp | open (Frank: `:self`, 2026-10-25) |
| W3 | statements from untrusted sayers are dropped (pre-filter pass 4), so a key card's statements vanish | **trust as facts, activation by rules** (Frank, 2026-10-25). Every verified statement enters the store with its sayer and stays dormant until a trust fact (`:self` trusts K for a type, scope and period) activates it. Delegation closure becomes recursive rules. "A key may speak about itself" is a default `:self` rule (the subject must equal the sayer). A statement naming another key (`:same-entity`) counts only with that key's signature; "K2 speaks for K1" is self-scoped for K1, "K1 speaks for K2" is not. Validity is the intersection of the statement's, the trust fact's and each delegation step's (the logic now in pdp `trust.clj`) | pdp | open |
| W3a | dormant raw facts must not be visible to policies (a policy matching a raw tuple bypasses trust) | either a discipline (policies read only activated predicates, enforced by a check on the policy set) or an engine feature (an origin that rules can lift from but policies can't see; today the authorizer's rules and policies share one scope) | stroopwafel, pdp | open |
| W3b | volume: anyone can submit statements | per-sayer caps or a relevance filter in the pre-filter; depends on W1 (bypass without it, denial of service with it) | pdp | open |
| W4 | revocation and negative permissions | revocation stays a **pre-filter**, applied before the reduction, with **revocation authority that is never derived**: (1) a sayer may always revoke its own statements; (2) `:self`; (3) revokers `:self` configures. No revocation through delegation, so there is no cycle with trust in Datalog and no negation in rules. Prefer short validity and positive freshness (a recent "still valid as of t" statement) where possible. Negatives only as `:self`'s deny policies or attenuating checks, never as statements from others. Fail closed when a revocation source is unavailable. docs/14 "Revocation and negatives" | pdp | open (Frank: pre-filter, 2026-10-25) |
| W5 | one signer per block; a card is signed by every key it names | start with N envelopes over the same card, joined on `:message-digest` (or the assertion `:id`s): `[:card-signed-by digest kid]`. Semantically identical to multi-sig when the reduction requires every signer. A multi-signer envelope in signet later, as an optimization: one object, one id for revocation, k-of-n thresholds (Frank likes it) | pdp, signet | open |
| W6 | cards to facts | `card->assertions` in signet: deterministic, plain data, no dependency on stroopwafel | signet | open |
| W7 | stroopwafel docs still describe the pre-0.11 token API | README and `context.md` rewritten on 2026-10-25; the use-case, LLM and websocket docs are marked as pre-0.11 | stroopwafel | done |

## Order (proposed)

0. **W1** (the fail-open fixpoint) before anything builds on the engine.
   **Key card (G13, D16) next.** Settle the dictionary against the prior
   art in docs/14 (MLS KeyPackage, Signal prekeys, CSR, DPoP, JWK/COSE,
   DID, OpenPGP, KERI, attestation), answer docs/14's questions, then write
   the card's chapter as design fiction. Profiles (G2), capabilities (G7),
   bindings (G3) and relying-party choice (G12) take their vocabulary from
   it.
1. Chapters 2 and 6 against today's API (more F-items expected).
2. Chapters 3–5 and 7 as design fiction: forces D1–D9 and D15.
3. Decisions with Frank, in this order: D1 (identity), D2 + D13 + D14
   (small, chapter-1 fixes), D3/D5 (profiles, capabilities), D15, D8/D9
   (seed), the rest.
4. First code slice: F1, F2, F5 (small, local), each with a failing-first
   test.
