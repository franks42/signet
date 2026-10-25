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
| G13 | **next to resolve** (Frank, 2026-10-25): a self-signed *key card*, an EDN map with `:type :signet/key-card`, exchanged instead of a bare kid. It is how keys, purposes, profiles and accepted formats reach a relying party; without it that knowledge is ad hoc and hard-coded. It subsumes G12's capability statement and G3's binding (signed by every key it names). Proof of possession only; trust is orthogonal | docs/14 "Key cards", D16 | open |
| G14 | cards as says-statements in stroopwafel-pdp: self-scoped assertions admitted without trust, `:named` keeping its sayer, a join over multi-signed cards (`:message-digest`), a sayer for derived aliases; signet's `card->assertions` | docs/14 "How this maps onto stroopwafel" | open |

## Order (proposed)

0. **Key card (G13, D16) first.** Settle the dictionary against the prior
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
