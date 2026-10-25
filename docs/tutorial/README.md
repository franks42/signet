# Tutorial: cryptography by reference (outline)

Status: **outline, 2026-10-24.** The tutorial is a design tool first: it
is written as the API we want, and each snippet is marked

- **[works]**: runs today, unchanged;
- **[change]**: works today in a different form; the tutorial shows the
  form we want, and the gap is a decision below;
- **[new]**: does not exist yet.

When chapters are written, every snippet runs as a test (CI), so
**[works]** stays true and a **[new]** snippet's failing test is its
specification. Nothing here is deployed, so signet's and the providers'
interfaces may change wherever the tutorial finds a better one.

## The claim

Application code names *who* and *what for*, never *how* or *with which
key bytes*. It holds references: an **identity** for itself, **kids** for
others. Which algorithm, which key, which provider (guarded memory, a
YubiKey, AWS KMS, an agent) and which signature format are decided by
configuration and by the purpose of the call. PKCS#11 has worked by
reference from the start (object handles, never key bytes); the tutorial
shows the same model without PKCS#11's interface.

Constraints the interfaces are judged against, even where unbuilt: an AWS
KMS provider (docs/13), P-256/P-384 and secp256k1 (docs/14), keys derived
from one seed (docs/14), the YubiKey through yubikey-sodium, and
nbb/browser ports.

## Glossary (to settle names first)

| Term | Meaning | Today |
|---|---|---|
| identity | a reference to *me*: one or more keys, bound together, each in some provider, used by purpose | partly: a signing-key handle; Noise sessions already accept one as the identity (`operations_test`) |
| kid | the public name of one key, `urn:signet:pk:<alg>:<b64>` | yes |
| handle | a reference to one secret key in a vault | yes (`KeyHandle`) |
| principal | how a relying party names someone else: a kid, or an identity's root kid plus its bindings | kid only |
| provider | where keys live and operations run | yes (phase 0 operations) |
| vault | a named set of entries with its provider | yes |
| purpose / profile | what an operation is for (`:signet`, `:x509`, `:cosmos`, `:eth`); fixes algorithm, pre-hash, encoding | no (docs/14) |
| binding | a statement, signed by both keys, that two keys belong to one identity | no (docs/14) |
| seed | a secret from which keys are derived; itself a vault entry | no |

## Chapters

### 1. Five minutes: sign, verify, box
`me`, a peer's kid, `sign`/`verify`, `box`/`unbox`. No algorithm names, no
key records. **[works]** for most, **[change]**: `box` takes a public-key
record today, `unbox` a kid (D1, D2).

### 2. References, not keys
What a handle, a kid and an identity are; why they print, log and
serialize safely; what the vault does with them; what never leaves
(`export-secret` and its acknowledgement). The PKCS#11 comparison: same
idea, without sessions, templates and attribute arrays. **[works]**,
**[change]** for identity.

### 3. One identity, several keys
An identity with an Ed25519 signing key, an X25519 key, a P-256 key and a
secp256k1 key; `(sign me tx {:for :cosmos})` picks the secp256k1 key and
its profile. The keys are bound (docs/14 bindings), so a relying party sees
one principal. **[new]** (D1, D3, D4).

### 4. Where keys live
The same code with the identity's keys in guarded memory, SoftHSM, the
YubiKey (through ykagent), and KMS. Configuration, not code, moves a key.
Capabilities: a provider that can't do an operation fails closed with
`:unsupported`. **[works]** for sodium/memory, **[new]** for the rest in
signet (yubikey-sodium has them as its own providers) (D5, D6).

### 5. Verifying: the relying party
Trust configuration by reference: accepted roots, kids, bindings,
validity. Valid, verified, authorized (README); where stroopwafel takes
over. **[works]** for `{:signer kid}`/`{:root kid}`, **[new]** for
bindings (D7).

### 6. Secrets that stay inside
Shared keys, Noise sessions, password keys, vault files: every derived
secret is an entry; the caller names outputs and destroys temporaries.
What the caller sees vs what the provider holds. **[works]** (phase 0 and
the secret-results change).

### 7. Keys from one seed
A seed as a vault entry; deriving keys for several algorithms with labels;
importing each derived key straight into its target provider; determinism
(derive twice, same kid) as the restore test; where the seed lives
afterwards, including wrapping it under a KEK held by KMS or the YubiKey
with its own access rules (docs/15). **[new]** (D8, D9).

### 8. Lifecycle
Generate, back up, rotate (a binding between old and new key), revoke,
recover. Each step by reference. **[change]**/**[new]** (D7, D10).

### 9. When things fail
YubiKey unplugged, agent locked, KMS offline or denying, wrong password.
What the developer sees: an error taxonomy. **[change]** (D11).

### 10. Testing without hardware
Stand-ins for every provider (the ops-only provider, SoftHSM, a fake KMS),
so tests run without a YubiKey or AWS. **[works]** in part.

### Appendix: the provider side
For provider authors: the operations, capabilities, secret results,
temporaries, and how KMS and the YubiKey map onto them.

## Seed and KEK

Moved to its own document, `docs/15-seed-and-kek.md`: the derivation
scheme (HKDF-Expand with the seed as the HMAC key), where the seed lives,
three KEK variants (KMS symmetric key, a KMS HMAC key *as* the seed, the
YubiKey) and importing derived keys into their targets. Chapter 7 tells
the user's side of it.

## Decisions the tutorial must settle

- **D1 Identity as the reference.** One identity reference for *me*;
  operations pick a key by purpose. (Frank: yes, 2026-10-24; the shape is
  to settle.)
- **D2 Others by kid.** Peers named by kid everywhere (`box`, `unbox`,
  `verify`, sessions); public-key records internal.
- **D3 Purposes and profiles.** The vocabulary (`:signet`, `:x509`,
  `:cosmos`, `:eth`, ...) and where the mapping to algorithm and profile
  lives (the identity's configuration).
- **D4 Bindings.** Two-signer statements; `:same-entity` vs `:speaks-for`
  with tags; transitivity (docs/14).
- **D5 Capabilities.** Per key: algorithm, profiles, operations, maximum
  message size, exportability, destroy semantics.
- **D6 Large messages.** Signet signs a framed digest when a provider's
  limit is below the message (KMS 4096 bytes, the agent's 512-byte frames).
- **D7 Trust configuration.** How a relying party names roots, kids and
  bindings.
- **D8 Seed as an entry**, and `derive-into!` as the operation that
  derives and imports in one step.
- **D9 Where the seed lives**: kept, offline (mnemonic or Shamir shares),
  or wrapped under a KEK (docs/15, variants A, B, C).
- **D10 Rotation and revocation** by reference.
- **D11 Error taxonomy**: `:unsupported` (never), `:unavailable` (retry),
  `:denied` (policy), `:locked` (needs unlocking).
- **D12 Sync or async** (to be settled in the tutorial). KMS and agents
  are network or socket calls; in nbb and the browser, I/O is
  asynchronous; libsodium.js initializes asynchronously once, then runs
  synchronously. Options: (a) synchronous API, remote providers only on
  JVM/bb; (b) promise-returning API everywhere; (c) synchronous core, with
  provider operations allowed to return deferred results and an async
  facade on cljs. Leaning (c); to decide with the cljs plan.

- **D13 Unknown options** (chapter 1, F2): reject option keys a function
  doesn't know, so a typo can't silently drop a property such as expiry.
- **D14 Values, not bytes** (chapter 1, F3, F4): `box`/`unbox` over EDN
  values like `sign-edn`, bytes as the lower layer; and whether kids
  travel visibly in a box by default.

- **D15 Choosing by the relying party** (docs/14): signed capability
  statements per key; Alice derives a matching key from her seed where an
  operation needs one; authenticated, with a policy floor.
- **D16 Key cards** (docs/14, next to resolve): a self-signed EDN map,
  `:type :signet/key-card`, naming an identity's keys with their purposes,
  profiles, accepted formats and validity, and signed by every key it
  names. This is how capabilities travel. Trust is orthogonal.
  Decided (2026-10-25, docs/14 "Decisions"): one card per identity; the
  X25519 key derived from Ed25519 is listed as its own `:agree` entry;
  agreement keys carry a proof level the reader computes (`:derived`,
  `:signed`, `:asserted`), with Noise sessions as the stronger option; no
  one-time cards; replacement by
  `:supersedes` and `:next`; a CEDN envelope.

The working list of gaps and their status: `TODO.md`.

## Order of work

1. This outline and the glossary.
2. Chapters 1–2 and 6 against today's API (mostly **[works]**): the
   baseline, and where the tutorial already reads well.
3. Chapters 3–5 and 7 as design fiction: they force D1–D9.
4. Decisions to Frank, then implementation in slices; chapters 8–10 as the
   slices land.
