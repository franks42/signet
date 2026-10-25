# More algorithms, more providers, and one identity across keys

Status: **design notes, 2026-10-24; nothing built.** Claims are marked
*verified* (read in signet's source or a primary document), *documented*
(from a standard or vendor documentation, from memory and not re-read
today), or *unverified*.

## The principle: 25519 at the core, other curves at the edges

The first ideal was 25519 only. That holds for signet's own protocols:
signed envelopes, box, shared keys, Noise sessions and vault files stay
Ed25519/X25519 on libsodium. Outside systems dictate other curves:

- **X.509**: P-256 (and P-384). Certificate authorities, TLS clients and
  PIV attestation work with the NIST curves.
- **Blockchains**: secp256k1 for Provenance, Cosmos, Ethereum and Bitcoin.
- **FIDO2/passkeys**: P-256 (ES256) in practice.

"libsodium everywhere" therefore means libsodium for what libsodium
implements, and a vetted library for the rest: BouncyCastle on the JVM, a
reviewed P-256 C library through FFI on bb, or a provider that holds the
key elsewhere (YubiKey, KMS, an agent). Phase 0 (docs/12) makes that
possible: signet's code calls provider operations and does not care where
a key lives.

## Where signet stands (verified in the source)

- **Kids already name their algorithm**: `urn:signet:pk:<alg>:<base64url>`
  (`signet.key/parse-kid`). Known: `ed25519` (32 bytes), `x25519` (32),
  `secp256k1` (33, compressed SEC1). Two curves can never give the same kid.
- **secp256k1 exists**, JVM-only (BouncyCastle, `signet.impl.jvm-secp256k1`,
  not on bb: SCI class allowlist). Signing is `SHA256withECDSA` with BC's
  random nonce and returns raw 64-byte r‖s. Verify accepts raw or DER.
- **No low-s normalization** in `secp256k1-sign`, **no recovery id**, and
  SHA-256 is the only pre-hash. So today's secp256k1 signatures are not
  usable for Ethereum (Keccak-256, needs `v`). Cosmos SDK chains reject
  high-s signatures (documented), so about half of today's signatures
  would fail there.
- **No P-256, no P-384.**

## Which provider can hold which algorithm

| Algorithm | libsodium | BouncyCastle / C library | YubiKey PIV | AWS KMS |
|---|---|---|---|---|
| Ed25519 | yes | yes | firmware 5.7+ (verified on Frank's 5.8 key, yubikey-sodium) | yes, messages ≤ 4096 bytes (docs/13) |
| X25519 | yes | yes | firmware 5.7+ (documented, not tried) | no |
| P-256 / P-384 | no | yes | yes | yes, sign and ECDH |
| secp256k1 | no | yes | no (documented: PIV has no secp256k1) | yes, signing |

YubiKey options for secp256k1 are the OpenPGP applet (unverified whether
and from which firmware) or a different device. KMS covers secp256k1
signing.

## Background: low-s and the recovery id

Two ECDSA details that decide whether a secp256k1 (or P-256) signature is
accepted outside signet. Neither exists for Ed25519.

**The signature.** An ECDSA signature is two numbers (r, s), each below the
curve order n (a constant per curve). The verifier combines r, s, the
message hash and the public key and checks that it gets r back.

**Low-s: every signature has a twin.** If (r, s) is valid for a message,
(r, n − s) is valid too: same message, same key, same r. Anyone can make
the twin, no private key needed. Exactly one of the two has s ≤ n/2; the
*low-s rule* says to publish that one. Normalizing after signing is one
comparison and one subtraction:

```
if s > n/2 then s := n − s
```

Blockchains require it because a transaction id is a hash over the
transaction, signature included: without the rule, anyone relaying a
transaction could swap in the twin, giving the same valid payment a
different id (*transaction malleability*, a well-known Bitcoin problem).
Bitcoin enforces low-s in relay policy, Ethereum since Homestead (EIP-2),
and Cosmos SDK chains, Provenance included, reject high-s in verification
(all documented).

Signet today (verified in `signet.impl.jvm-secp256k1/secp256k1-sign`)
returns whatever s BouncyCastle produces. The nonce is random, so s is in
the upper half about half the time: roughly every second signature would
be rejected by Cosmos or Ethereum. Signet's own verifier accepts both
twins, which is correct ECDSA but means "valid" does not imply "unique".

Inside signet this matters only where signature bytes act as an
identifier. `signet.chain` links each block to the previous block's
signature (`prev-sig`), so a block whose signature can be swapped for its
twin could be re-signed by a third party into a different but valid
chain. Today that looks out of reach (read, not tested): the chain's root
is documented as an Ed25519 keypair and later blocks are signed by
ephemeral Ed25519 keys. It becomes a question the day a chain root can be
secp256k1 or P-256. Ed25519 has no twin: RFC 8032 has verifiers reject the
non-canonical form, and libsodium does.

**The recovery id: the public key from the signature.** From (r, s) and
the message hash one can compute the public key that made the signature,
up to a small ambiguity: in practice two candidate keys. The *recovery id*
`v` (0 or 1; also written 27/28, or folded with the chain id under
EIP-155) says which.

Ethereum needs it: a transaction does not contain the sender's public key
or address. Nodes recover the public key from the signature (`ecrecover`)
and derive the address from it, so an Ethereum signature is 65 bytes,
r‖s‖v. Cosmos does not: its transactions carry the signer's public key,
and 64 bytes of r‖s suffice.

Signet returns 64 bytes r‖s, no `v`. Hardware and KMS are the same: a
YubiKey or KMS `Sign` returns only (r, s), usually DER-encoded. A provider
computes `v` afterwards: recover both candidates, keep the index of the one
equal to the known public key. Cheap, and it needs only the public key.

**Why one key needs several outputs.** The same secp256k1 key and message
must give different bytes per destination:

| | pre-hash | s | output |
|---|---|---|---|
| signet today | SHA-256 | either half | r‖s, 64 bytes |
| Cosmos / Provenance | SHA-256 | low half | r‖s, 64 bytes |
| Ethereum | Keccak-256 | low half | r‖s‖v, 65 bytes |

A profile (next section) fixes all three, so a caller says "sign for
Cosmos" and needs to know none of this.

## Signature profiles

`-sign` today means "sign these bytes with this key". For ECDSA, the same
key and message give signatures in different shapes, and an outside
verifier accepts only its own. The proposal: a provider signs under a
named **profile**, and the profile fixes every choice.

| Profile | Pre-hash | Encoding | low-s | Extra |
|---|---|---|---|---|
| `:ed25519` | none (EdDSA, pure) | 64 bytes | n/a | signet's default |
| `:p256/x509` | SHA-256 | DER | not required | X.509, TLS, PIV |
| `:p256/webauthn` | SHA-256 over authenticatorData ‖ SHA-256(clientData) | DER | not required | what a passkey produces; see below |
| `:secp256k1/cosmos` | SHA-256 | raw r‖s, 64 bytes | required | Cosmos SDK, Provenance |
| `:secp256k1/eth` | Keccak-256 | r‖s‖v, 65 bytes | required (EIP-2) | needs the recovery id |

Consequences for providers:

- **The provider normalizes, signet checks.** If a backend returns high-s
  (BouncyCastle; KMS documents no normalization, unverified), the provider
  replaces s by n − s. A conformance check verifies every signature against
  its profile, in line with yubikey-sodium's rule "detect quirks, add a
  check for each".
- **Pre-hashing happens in the provider or on the host, per backend.**
  KMS has no Keccak: an `:secp256k1/eth` signature is a KMS `Sign` with
  `MessageType: DIGEST` over a host-computed Keccak-256. YubiKey PIV
  always signs a host-computed digest.
- **The recovery id** is not returned by KMS or PKCS#11; the provider finds
  `v` by trying both candidates against the public key.
- **Nonces.** Hardware and KMS use random nonces; BouncyCastle can use
  RFC 6979 (deterministic). Signatures then differ between providers for
  the same key and message. Verifiers don't care; tests that compare bytes
  must.
- A provider advertises `(alg, profile)` pairs; asking for one it lacks
  fails closed (`:unsupported`).

**Kids for new algorithms** follow the existing scheme:
`urn:signet:pk:p256:<compressed 33 bytes>`, `urn:signet:pk:p384:<49
bytes>`.

**Key agreement.** `-x25519-dh` stays named after its curve; box and
Noise stay X25519-only. If P-256 ECDH is needed (KMS's ECDH keyring,
X.509-adjacent protocols), it is a sibling operation, not a generalization.

## Several keys from one seed

All of these can be derived from one random master seed, each through its
own labelled derivation (never the same raw bytes as several keys):

```
master = 32 random bytes                        (the one secret to back up)
ed     = HKDF(master, info="signet/derive/v1/ed25519")    32 bytes, any value
p256   = HKDF(master, info="signet/derive/v1/p256")       -> scalar d, 1 <= d < n
p384   = HKDF(master, info="signet/derive/v1/p384")       48+ bytes -> scalar
k1     = HKDF(master, info="signet/derive/v1/secp256k1")  -> scalar
```

- Ed25519 takes any 32 bytes as a seed (libsodium
  `crypto_sign_seed_keypair`).
- ECDSA scalars must lie in [1, n−1]: reject and retry with a counter, or
  take 64 extra bits and reduce, d = (c mod (n−1)) + 1 (FIPS 186-5's
  method with extra random bits; documented).
- Labels keep the keys independent: a leak in one implementation (a biased
  ECDSA nonce, say) does not expose the others.
- Prior art: BIP32 (secp256k1 from a seed, HMAC-SHA512 keyed "Bitcoin
  seed") and SLIP-0010 (the same for Ed25519 and P-256, one HMAC key per
  curve); documented, constants not re-checked.

Trade-offs: one seed backs up every key, and is the single point of
compromise (the recovery-key trade, docs/10). Derived keys are born in
software: they can be imported into KMS or a YubiKey, but they existed
outside the hardware once. Keys generated on a device cannot be derived.

## One identity, several keys (for SPKI/SDSI assertions and stroopwafel)

Frank's idea: an Ed25519 key states that a P-256 key identifies the same
entity, the two keys cross-sign so a relying party can check that one
holder has both private keys, and stroopwafel's policy reduction then
treats assertions by either key as equivalent.

This makes sense, and it is the right place for it: signet supplies keys,
signatures and the statement format; stroopwafel decides what a binding
means.

### Why both keys must sign

A statement signed by the Ed25519 key alone ("K_p256 is also me") proves
only that the Ed25519 holder *claims* the P-256 key. Anyone can claim any
public key. If Mallory claims Alice's P-256 key, Alice's P-256 signatures
start counting as Mallory's: an unknown-key-share or misattribution attack
(the reason X.509 requests carry proof of possession and Keybase's
sigchains sign in both directions).

So the binding is **one statement, signed by both keys**:

```clojure
{:type     :signet/key-binding
 :v        1
 :keys     ["urn:signet:pk:ed25519:…" "urn:signet:pk:p256:…"]  ; both kids, sorted
 :relation :same-entity          ; or :speaks-for, see below
 :valid    {:not-before … :not-after …}
 :nonce    "…"}                  ; makes each binding unique
```

Each key signs the canonical bytes of the whole statement, both kids
included, so neither signature can be lifted into another binding. Each
signature uses its own profile: `:ed25519` for one, and for the P-256 key
whatever its holder can produce:

- **YubiKey PIV or KMS**: `:p256/x509` over the statement's bytes.
- **A passkey (FIDO2)**: it never signs arbitrary bytes, only WebAuthn
  assertions. Use the SHA-256 of the statement as the challenge; the
  binding then carries the assertion (authenticatorData, clientDataJSON,
  signature), and verification checks the challenge equals the hash.
  That is the `:p256/webauthn` profile, and it would tie signet
  identities to passkeys. yubikey-sodium already reaches FIDO2 through
  libfido2.

### Equivalence or "speaks for"

A symmetric `:same-entity` makes the identity as weak as its weakest key:
a software P-256 key in a browser would carry the authority of a
hardware-held Ed25519 root. SPKI's own vocabulary is directional: K1
*speaks for* K2, optionally only for some tags.

The proposal: the binding names one relation, stroopwafel derives
directional facts from it, and **policy chooses**:

- `:same-entity`: both directions, every tag.
- `:speaks-for` with a tag restriction, e.g. the P-256 key speaks for the
  Ed25519 identity only for `(tag (x509-tls))`, never the other way.

In Datalog, roughly:

```
speaks_for(B, A, Tag) :- binding(Id, A, B, same_entity), both_signed(Id),
                         valid(Id), Tag = any.
speaks_for(A, B, Tag) :- binding(Id, A, B, same_entity), both_signed(Id),
                         valid(Id), Tag = any.
speaks_for(B, A, Tag) :- binding(Id, A, B, speaks_for, Tag), both_signed(Id),
                         valid(Id).
acts_as(K, P, Tag)    :- speaks_for(K, P, Tag).
```

An assertion signed by K then counts as P's for tags where
`acts_as(K, P, Tag)` holds. That is the reduction Frank described, with
the strength question made explicit.

### Things to decide

- **Transitivity.** A ≡ B and B ≡ C makes A ≡ C. That is the point (one
  entity, many keys), but it also lets one weak binding join two
  identities. Options: no transitive closure (only direct bindings), a
  depth limit, or closure only through a designated root key.
- **Revocation.** Revoking either key must void every binding naming it;
  revoking a binding needs a statement signed by *either* key (a
  compromised key must not be able to keep a binding alive).
- **Which key is the root.** Natural choice: the hardware-held Ed25519 key
  is the entity's root, and other keys get `:speaks-for` with tags.
- **Rotation is a special case.** stroopwafel's root rotation
  (docs/spki-sdsi-vs-biscuit.md, 5.3.2) has the new key re-sign the old
  key's assertions. A cross-signed `:same-entity` binding between old and
  new key, valid for an overlap window, does the same with one statement.
- **Where the statement format lives.** signet: the binding is a signed
  envelope with two signers (signet's envelopes have one signer today).
  stroopwafel: what a binding means for policy.

## Choosing by the relying party (Frank's question, 2026-10-24)

Idea: Alice reads Bob's key type from his kid, which hints at the formats
and algorithms Bob supports; since Alice can derive a key of any type from
her seed, she can match Bob without either of them configuring anything.

It works, with three refinements.

**1. The key type is a hint; a capability statement is the authority.**
A P-256 key says which curve, not which format: ECDH-ES (JWE), HPKE
(RFC 9180), ECIES, CMS, or AWS's ECDH keyring all fit one P-256 key. So
Bob publishes, signed by his identity, which profiles each key accepts:

```clojure
{:type :signet/capabilities :v 1
 :kid  "urn:signet:pk:p256:…"
 :accepts [:hpke/p256-sha256-aes128gcm]       ; encrypt to me like this
 :verifies [:ed25519 :p256/x509]}               ; I can check these signatures
```

Precedents (documented): OpenPGP's key flags and preferred-algorithm
subpackets, S/MIME's capabilities attribute, JWK's `use` and `alg`, DID
documents' verification methods, TLS's cipher-suite negotiation.

**The statement is also what to exchange instead of a bare kid**
(Frank, 2026-10-24: "a signed uri with the key"). A kid already carries
the whole public key, so the signature does not add the key; it adds
*proof of possession*: the key is a valid point and someone holding its
private key made the statement. A self-signed kid alone is weak (it is
replayable, says nothing about what the key is for, and invalid keys
already fail closed when used: libsodium rejects small-order keys). Signed
together with the capabilities, purpose, expiry and bindings, it becomes a
*key card*, like an OpenPGP self-signature on a user ID. Self-signed means
possession, not trust: whether this is Bob's card is still learned
authentically, by fingerprint, or by a signature from someone Alice
trusts (SPKI). The kid stays the reference; the card is how it travels.

**2. What Alice needs to match depends on the operation.**

- **Encrypting to Bob, sender-authenticated** (signet's box: static-static
  DH): Alice needs a key **on Bob's curve**, because Diffie-Hellman only
  works within one curve. This is where the seed helps: Alice derives her
  P-256 key, binds it to her identity (a key binding, above), and Bob
  checks the sender through the binding.
- **Encrypting to Bob, anonymous** (an ephemeral sender key, as in HPKE's
  base mode): Alice needs no key of her own; Bob's key and accepted
  profile are enough.
- **Signing for Bob**: Bob's own key type is irrelevant; what matters is
  what Bob can *verify* (`:verifies`). A JWT or X.509 verifier that only
  knows ES256 makes Alice sign with her P-256 key.

**3. Negotiation must be authenticated and have a floor.**

- **Downgrade**: an attacker who can change Bob's statement in transit
  steers Alice to the weakest profile. The statement is signed by Bob's
  identity root, and Alice obtains that root authentically (the same
  problem as obtaining Bob's kid at all).
- **Floor**: Alice's policy can refuse profiles (no forward secrecy for
  some data, no curve below a level) and fail closed rather than
  "accommodate" down to them.
- **Preference**: among profiles both support, a fixed order (Alice's
  policy), not Bob's.

**Two consequences worth noting:**

- **Pairwise keys.** The same seed can derive a different key *per relying
  party* (Bob's kid in the label), as passkeys do per site: Bob and Carol
  then cannot link Alice by her key. Linkable identity via bindings, or
  unlinkable pairwise keys, becomes a per-relationship choice.
- **One encryption format for every curve.** Box v2 is X25519 and
  ChaCha20-Poly1305. Rather than a signet-specific box for P-256, HPKE
  (RFC 9180) covers both: DHKEM(X25519) and DHKEM(P-256) suites, with an
  authenticated mode (AuthEncap) matching box's sender authentication. Its
  X25519/HKDF-SHA-256/ChaCha20-Poly1305 suite can be built from libsodium
  primitives (unverified: no libsodium HPKE API; an implementation would be
  checked against RFC 9180's test vectors). A possible box v3; not
  proposed yet.

## Key cards: how keys and capabilities travel (next to resolve)

Frank, 2026-10-25: without a card, a relying party learns what a key is
for and what it supports in some ad hoc, hard-coded, unspecified way. So
the card comes before profiles, HPKE and the seed: it is where all of
them become visible to the other side. It is defined in EDN, as a map
with a `:type`, and signed as a signet envelope.

**Trust is orthogonal.** A card proves possession (whoever signed it holds
the keys it names) and states properties. Whether the card belongs to
"Bob", and whether Bob may do anything, is decided elsewhere: by how the
kid was obtained, by SPKI/SDSI certificates, by stroopwafel policy.
Nothing in the card changes that.

### What existing cards do, and what to take

RFC 9420 is verified (sections 7 and 10 read on 2026-10-25). The others
are documented from memory and not re-read for this section.

| Spec | Signed by | What to take |
|---|---|---|
| MLS KeyPackage (RFC 9420) | its own signature key (label `"KeyPackageTBS"`) | the closest model. Carries a signature key, an HPKE `init_key`, a leaf `encryption_key`, **capabilities** (versions, cipher suites, extensions, proposals, credential types) and a **lifetime** (`not_before`, `not_after`). Rules: the sender must check the lifetime and the receiver should; applications must set a maximum lifetime and reject longer ones; every extension used must be listed in capabilities; the encryption key must differ from `init_key`; KeyPackages are meant for one use (reuse enables replay), with an optional "last resort" package; a client must support everything it advertises (13.4) |
| Signal prekey bundle (X3DH/PQXDH) | the long-term identity key signs the prekey | an identity key vouching for an encryption key, which is our binding applied to `:agree` keys |
| PKCS#10 CSR, S/MIME capabilities (RFC 2986, RFC 8551) | the key it contains | proof of possession; algorithm preferences, in order, as an attribute. Replayable (no freshness) |
| DPoP (RFC 9449) | the key in its header | freshness for a *presentation*: issued-at, a unique id, the audience (method and URL) |
| JWK / COSE_Key (RFC 7517, RFC 9052) | (a key, not a card) | the vocabulary: `use`, `key_ops` (sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits), `alg`, and `crit` for must-understand headers; RFC 7638 thumbprints |
| W3C DID document | the controller | keys by role (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityDelegation`); service endpoints; `did:key`, an identifier that is the key, as signet's kid is |
| OpenPGP self-signature (RFC 9580) | the primary key | key flags (certify, sign, encrypt communications, encrypt storage, authenticate); preferred algorithms in order; key expiration; subkeys bound by the primary key, with a back-signature by the subkey (cross-signing) |
| KERI | the current keys | pre-rotation: commit now to the hash of the next key, so a stolen current key cannot rotate the identity |
| WebAuthn / YubiKey PIV attestation | the authenticator's attestation key | evidence that the key was generated in hardware and cannot be exported; trusting it is a separate question (the vendor's root) |
| X.509, SSH certificates | an issuer | validity periods, key usage; the issuer part is trust, so it is out of scope here |

### The dictionary (draft)

| Key | Meaning | From |
|---|---|---|
| `:type` | `:signet/key-card` | JOSE `typ`, MLS structures |
| `:v` | card format version | MLS `version` |
| `:keys` | the keys this card names, each a map described by the rows below | DID verification methods, MLS (several keys in one package) |
| `:kid` (per key) | the key itself; the kid carries the algorithm and the public key | `did:key`, JWK |
| `:purposes` (per key) | what the key is for: `#{:sign :agree :authenticate :certify}`; a relying party refuses other uses | JWK `key_ops`, OpenPGP key flags, DID roles |
| `:profiles` (per key) | signature profiles the key produces (`:ed25519`, `:p256/x509`, `:secp256k1/cosmos`) | the profiles in this doc |
| `:accepts` (per key) | encryption formats the key can open, in preference order (`:box/v2`, `:hpke/p256-sha256-aes128gcm`) | MLS cipher suites, OpenPGP preferences, S/MIME capabilities |
| `:verifies` | signature profiles the holder can check, in order | MLS capabilities, TLS `signature_algorithms` |
| `:formats` | envelope and protocol versions the holder speaks | MLS `versions` |
| `:critical` | keys the reader must understand, or else reject the card | JOSE `crit`, MLS (extensions listed in capabilities) |
| `:not-before`, `:not-after` | validity; the relying party also enforces its own maximum | MLS `Lifetime`, X.509 validity |
| `:next` | hash of the next key or card (pre-rotation) | KERI |
| `:attestation` | optional hardware evidence, per key (YubiKey PIV attestation, WebAuthn) | WebAuthn, PIV |
| `:names` | optional claimed names: assertions, not facts | OpenPGP user IDs, SDSI local names |
| `:services` | optional endpoints (agent, inbox) | DID services |

When the card is presented to one relying party, it goes inside a fresh
envelope (`:aud`, `:iat`, a nonce), DPoP-style. The card itself stays
reusable.

```clojure
{:type :signet/key-card :v 1
 :keys [{:kid "urn:signet:pk:ed25519:…" :purposes #{:sign :certify}
         :profiles [:ed25519]}
        {:kid "urn:signet:pk:x25519:…"  :purposes #{:agree} :accepts [:box/v2]}
        {:kid "urn:signet:pk:p256:…"    :purposes #{:sign :agree}
         :profiles [:p256/x509] :accepts [:hpke/p256-sha256-aes128gcm]
         :attestation {:type :yubikey/piv :cert "…"}}]
 :verifies [:ed25519 :p256/x509]
 :formats  {:envelope [1] :box [2]}
 :not-before 1792886400000 :not-after 1824422400000
 :next "sha256:…"}
```

**Signed by every key it names.** Each key signs the card: the root
first, then every other key over the same bytes. That makes the card both
the proof of possession and the multi-key binding from "One identity,
several keys" above, so there is one statement rather than two
mechanisms. Keys that sign nothing (`:agree` only) are covered by the
other keys' signatures, with a proof level the reader computes (decision
3 below).

### Rules for the reader (draft, after MLS 10.1)

1. `:type` and `:v` are known and every key in `:critical` is understood;
   otherwise reject the card.
2. Every listed signing key's signature verifies over the canonical card.
   Each `:agree` key gets a proof level computed by the reader
   (`:derived`, `:signed`, `:asserted`; decision 3). Policy may require a
   minimum level per use.
3. The current time is within `:not-before`/`:not-after`, and the span
   does not exceed the reader's maximum.
4. Use a key only for its `:purposes`. Choose among `:accepts` and
   `:verifies` by the reader's own order and floor (D15), never by the
   card's order.
5. The holder must support everything the card advertises (MLS 13.4). If
   the holder can't open a format it lists, that is the holder's error.
6. Accepting the card establishes nothing about trust.

### A card is a set of statements by its keys (Frank, 2026-10-25)

A verified card is an assertion in the stroopwafel sense: it binds names
and statements to a key. The sayer is the key (the principal is the
public key, as in SPKI). There are two kinds of identifier for it:

- **Self-certifying aliases** are identifiers the relying party derives
  itself from the public key: the kid, a hash of the key, or any URI
  scheme that contains the whole key or its hash (`did:key`). The
  equivalence of these aliases with the key is *computed* by the reader,
  not asserted by anyone, so it needs no sayer and no trust. Two
  conditions:
  - The alias must name its derivation (algorithm and hash), as a
    multihash does.
  - The key must be in one canonical encoding before it is hashed. A
    P-256 or secp256k1 point has a compressed and an uncompressed form,
    which give two hashes for the same key.
- **Asserted names** cannot be derived: a UUID, a nickname, an account,
  an email address. These are always kept with their sayer: "K says
  `name` is N", which is SDSI's local name `(K N)`. They are never a fact
  about the key. Such a name means something outside K's own namespace
  only through someone the relying party already trusts.

Reading a card therefore produces facts, each tagged with its sayer and
validity. Examples: K says "my purposes are …"; K says "I accept …"; K1
says K2 is the same entity, and K2 says the same about K1; K says its
next key hashes to H. Whether "K1 and K2 are the same entity" follows from
those mutual statements is a *rule* in the relying party's policy, not
something the card decides.

**Consequence: a reduction engine.** Several questions are policy
reductions over these facts plus local policy, not lookups:

- whom a name refers to;
- whether two keys count as one principal;
- which profile to use with Bob (D15: Bob says he accepts X, combined
  with the local preference order and floor);
- whether a statement is still in scope.

SPKI's 5-tuple reduction (issuer, subject, delegation, authorization,
validity) and stroopwafel's Datalog-style rules are this kind of engine.
The proposed layering:

- **signet** verifies signatures, checks the card's format rules (above)
  and emits says-facts with validity. It doesn't depend on the engine.
- **stroopwafel** reduces facts and local policy to decisions.
- In between, simple decisions (one card, no names, fixed policy) can be
  plain code at first, as long as they are expressed as the same facts.

Open points for the engine:

- Revocation and replacement (a newer card, a `:next` commitment) are
  non-monotonic. Resolved below: they are filtered out before the
  reduction ("Revocation and negatives").
- Time is an input to the reduction (each fact's validity window), not
  something checked once at load time.

### How this maps onto stroopwafel today (source read 2026-10-25)

Read: stroopwafel 0.11.0 (`c92ab8c`) and stroopwafel-pdp (`dfaa477`, the
`stroopwafel.pdp.spki.*` namespaces), plus stroopwafel's
`docs/generic-assertion-schema.md` and `docs/library-separation-plan.md`.

**The layering already exists.** Stroopwafel is now a pure Datalog engine
with no dependencies (`evaluate`: blocks of facts, rules and checks in;
`{:valid? …}` out). signet signs and verifies. stroopwafel-pdp verifies
blocks, filters them and calls the engine. A card reader in signet that
outputs plain data fits that design without new dependencies.

**The shapes already fit.**

- An SPKI assertion block (`stroopwafel.pdp.spki.assertion`) is a signet
  envelope whose message is
  `{:not-before … :not-after … :assertions [{:id :type :statement} …]}`.
  Its sayer is the signer's kid.
- The pre-filter turns each surviving assertion into a fact
  `[sayer ts not-before not-after type id & statement]`.
- Templates turn those facts into predicates: `[:can …]`, `[:named ?key
  ?name]`, `[:delegated …]`, `[:revoked-… …]`.

A card's statements are new assertion types in the same tuple, for
example `:key-purposes`, `:accepts`, `:verifies`, `:same-entity` and
`:next`. Proposal: the card stays the readable map from the dictionary
above (the protocol-facing form), and signet has a deterministic
`card->assertions` that produces this tuple shape. A card could also be
an assertion block directly, but it would lose its per-key structure.

**Four gaps, found in the source:**

1. **Untrusted sayers are dropped** (pdp pre-filter pass 4: an assertion
   survives only if its sayer is a trust root or delegated for that
   type). A card is signed by a key nobody trusts yet, so all of its
   statements would vanish. Needed: *self-scoped* assertions. These are
   statements whose subject is the sayer itself (my purposes, my formats,
   my names in my namespace, my other keys). They are admitted without
   trust because they bind only the sayer; policy rules decide whether
   they matter.
2. **The name-binding template drops the sayer** (`[:named ?key ?name]`).
   That is sound only while every surviving name comes from a trusted
   sayer, so that names are effectively the relying party's own. Once
   self-asserted names are admitted, a name must stay attached to its
   sayer: `[:named ?sayer ?key ?name]`, the SDSI name `(K N)`.
3. **One signer per block** (a signet envelope has one signer). A card
   signed by every key it names becomes N envelopes over the same card.
   `verify-block` already returns `:message-digest`, so the reader can
   emit `[:card-signed-by digest kid]` and a rule can join on the
   digest.
4. **Derived aliases have no sayer yet.** The relying party computes them
   itself (kid ↔ key hash ↔ `did:key`). They are injected facts, which is
   open question 4 in `generic-assertion-schema.md` (a special
   `:injected` sayer or bare facts). Self-certifying aliases are the
   clean case for it: they are true by construction. Frank's answer
   (2026-10-25) is `:self` as the sayer. That matches the trust anchor
   in `stroopwafel-tutorial/notebooks/00_new_model_sketch.clj`: the
   local PDP, the only axiom `[:trusted :self]`, with trust roots as
   `:self` assertions. It is SPKI's `Self` at the root of an ACL. The
   condition: a sayer always comes from signature verification and never
   from a message, so nothing signed can claim to be `:self`.

**A fifth finding, beyond cards: the engine fails open at its limit.**
Rule evaluation stops silently at 100 iterations or 1000 facts. A
`:reject` check or a `:deny` policy over facts that were never derived
then passes. This was reproduced on 2026-10-25 with a transitive closure
over 50 edges. It matters here because equivalence closure over bound
keys grows quadratically (TODO W1).

**Revocation and time are already outside Datalog.** The engine has no
negation in rule bodies. Denial is expressed through `:reject` checks and
`:deny` policies (closed world). In the pdp, validity (pass 2, with a
verifier cap `:max-block-ttl-ms`) and revocation (passes 5 and 6) are
filters applied before evaluation. That is the "short validity plus a
check outside the engine" approach recommended above. A card's
replacement (a newer card, `:next`) would be one more pre-filter pass,
not a Datalog feature.

### Resolving the gaps (Frank, 2026-10-25)

- **Gap 1, untrusted sayers: trust becomes facts, activation becomes
  rules.** Every verified statement enters the store with its sayer and
  stays dormant until a trust fact activates it (`:self` trusts K for a
  type, a scope and a period). When such a fact is added later,
  statements that were already present start to count. Delegation closure
  becomes recursive rules, and explain mode shows why something was
  trusted. "A key may speak about itself" becomes a default `:self` rule
  (subject = sayer). This replaces the pdp's pass 4 and answers open
  question 1 of `generic-assertion-schema.md` in favour of the engine.
  Three conditions:
  - Dormant raw facts must be invisible to policies, since a policy that
    matched a raw tuple would bypass trust. This needs a discipline that
    is checked, or an engine origin that rules can lift from and policies
    can't see.
  - Per-sayer caps against flooding (and W1 fixed first).
  - Validity is the intersection along the chain.
- **Gap 2, names: one predicate, `[:named-by ?sayer ?key ?name]`.** The
  local namespace is `:self`'s: `[:named-by :self …]`, derived from K's
  bindings when `:self` trusts K for names. This is SDSI, where all local
  names are relative to `Self`.
- **Gap 3, several signers: identical statements signed separately mean
  the same as one multi-signed statement**, as long as the reduction
  requires every signer. Start with N envelopes joined on the message
  digest. The envelopes themselves differ (each carries its own signer,
  timestamp and request id), so the join must not be on the envelope. A
  multi-signer envelope comes later as an optimization: one object (no
  partial delivery), one id for revocation, k-of-n thresholds.
- **Gap 4, injected facts: `:self` as their sayer.**

### Revocation and negatives: kept out of the reduction

Revocation and negative permissions are where policy evaluation becomes
ambiguous: a deny by one sayer against an allow by another, order
dependence, revocations of revocations. Frank's position (2026-10-25):
treat revocation specially and filter revoked statements out *before*
the reduction. The reduction then stays monotonic: adding facts can only
add conclusions.

Moving trust into Datalog (gap 1) makes one point delicate: who may
revoke. If revocation authority were itself derived by rules, revocation
would depend on trust, and trust (via revoked delegations) on
revocation. That is a cycle which needs stratified negation to resolve.
The way out is that **revocation authority is never derived**:

1. **A sayer may always revoke its own statements.** That is
   unambiguous, since it only removes the sayer's own words, and it needs
   no trust.
2. **`:self` may revoke anything.**
3. **Revokers that `:self` configures** (a revocation service, an
   organisation's root), named directly, not reached by delegation.

The pre-filter can then apply revocations as a plain function before any
rule runs: no negation, no cycle. A revoked delegation never enters the
store, so the trust computed by rules is already clean.

Alternatives and complements, each avoiding a revocation where possible:

- **Short validity** (SPKI's preference). A statement expires before
  revocation would matter; reissuing it replaces revoking it.
- **Positive freshness**, the monotonic form of revocation: a policy
  requires a recent "K is still valid as of t" statement from a status
  service (OCSP-like, instead of a CRL). A missing statement then means
  deny under the closed world, without any negation, and an unreachable
  status service fails closed by itself.
- **Rotation instead of revocation:** the `:next` commitment replaces a
  key without a revocation statement.
- **Negatives only from `:self`**: deny policies, or attenuating checks
  inside a token, which can only make a decision fail (Biscuit's model).
  A "deny" asserted by another sayer is not a statement type.

Open: when a *key* is revoked, are its statements from before the
revocation still valid? The compromise time is usually unknown, so the
conservative answer is that all of them are revoked. Also open: what the
pre-filter does when a revocation source is unavailable (fail closed, or
accept within a configured staleness).

### Decisions (Frank, 2026-10-25)

1. **One card per identity.** A one-key card is the special case. The
   card is also the binding between the keys. Adding a key re-issues the
   card (every key signs again), with `:supersedes` pointing at the old
   one.
2. **X25519 derived from Ed25519 stays, for the default 25519 identity.**
   The card lists it as its own `:agree` entry. Because the conversion
   uses public keys only, a reader checks the link the way it recomputes
   a kid: it is a self-certifying alias, and the Ed25519 signature covers
   it. P-256 and secp256k1 use separate keys for signing and for
   agreement. (From memory, not re-checked: Thormarker 2021 analysed
   Ed25519 plus an X25519-based KEM with a shared key pair and found it
   secure under its assumptions; Signal's XEdDSA reuses keys in the other
   direction.)
3. **Agreement keys are asserted by the card; their proof is graded and
   visible** (revised the same day, after the conflict with decision 2:
   a separate P-256 agreement key is not derivable, so requiring
   derivation would rule out P-256 encryption). Frank's reasoning: trusting
   an encryption key that the card asserts but that hasn't proven
   possession is less harmful than trusting an unproven signing key. A
   wrong encryption key leaks confidentiality to whoever holds it, while
   an unproven signing key would let someone *speak as* the identity.
   Signing keys always prove possession by signing the card. An `:agree`
   key carries one of these proof levels, which the reader computes; the
   card cannot claim them:
   - `:derived`: the reader derives it from a signing key on the card
     (X25519 from Ed25519). Equivalent to proven.
   - `:signed`: the key pair signed the card itself (possible for
     P-256 and secp256k1, where the same key pair can do ECDSA). That
     signature is the key's only one, so no protocol uses it for both
     signing and agreement.
   - `:asserted`: covered only by the other signatures on the card.

   A reader's policy sets the minimum level per use; the default accepts
   `:asserted`.

   **The attack vector to be aware of** is a card listing an encryption
   key whose private key someone else holds. Messages boxed to it can be
   read by that party, and an unknown key-share is possible: Alice
   believes she writes to Bob, but Carol can read. Who can cause it:
   - *Not an outsider.* Adding a key changes the card bytes, so it
     requires the card's signing keys. An outsider who has those keys has
     taken over the identity anyway.
   - *The holder, by mistake or on purpose.* A malicious holder can leak
     plaintext anyway; a mistaken one is what the proof levels catch.
   - *A compromised issuing system* (for example, card generation in an
     environment an attacker controls). Here `:signed` or `:derived` help,
     because the attacker would also need that key's private half to
     sign.

   **The more secure alternative: a session.** In a Noise handshake each
   side proves possession of its static key implicitly: without the
   private key, the handshake fails. So a session to an `:asserted` key
   either proves the key or fails. This is the interactive challenge
   (option b), for free. Limits: signet's sessions are
   `Noise_KK_25519_…`, and Noise defines only 25519 and 448, so for P-256
   the alternatives are `:signed` cards or a TLS-style handshake. A box,
   in contrast, is accepted by the sender without the recipient ever
   proving anything.
4. **No one-time cards for now.** Reusable cards with short validity.
   If forward secrecy for asynchronous first messages becomes a
   requirement, follow MLS and Signal (one-time prekeys plus a last-resort
   key).
5. **Replacement:** a newer card carries `:supersedes <digest>` and is
   signed by the old root key. `:next` commits to the next root key, so a
   stolen current key cannot take over the identity, and a lost one can
   be succeeded. Revocation goes through the pre-filter (W4).
6. **Canonical form:** a signet envelope (CEDN) over the card map.

**Forward secrecy, raised with decision 2 ("the default should use
ephemeral keys").** What each mode gives:

| Mode | Keys | Forward secrecy |
|---|---|---|
| box today (verified in `encryption.cljc`) | static-static X25519, a fresh HKDF key per message (salt = nonce) | none: a later compromise of either static key opens past boxes |
| ephemeral sender + static recipient (HPKE base/auth mode) | a fresh sender key per message; auth mode adds static-static for sender authentication | only against compromise of the *sender's* key; a compromise of the recipient's static key still opens every past message |
| one-time prekeys (Signal, MLS) | the recipient publishes single-use keys | yes, for asynchronous messages; needs one-time cards (decision 4: not now) |
| Noise KK session (verified in `session.cljc`) | ephemeral on both sides | yes; both sides must take part |

So "ephemeral by default" can mean two things. For **boxes**, the
achievable default is an ephemeral sender key with static authentication
(HPKE auth mode, the box v3 candidate). It is better than today (sender
compromise no longer exposes past messages, and it matches the P-256
path), but it is not forward-secret against compromise of the recipient's
key. Real **forward secrecy** needs either both parties online (signet's
Noise sessions, which exist) or one-time prekeys (deferred). Proposal: a
box v3 with an ephemeral sender key (HPKE auth mode, X25519 and P-256
suites); sessions for forward secrecy; a card's `:accepts` names which
ones the holder supports. To decide with box v3 (TODO G15).

## Open decisions (Frank's)

- Signature profiles as the extension of `-sign` (recommended before the
  first non-25519 provider).
- Fix today's secp256k1 path (low-s at least) or leave it until a chain
  profile is built.
- Before a chain root may be secp256k1 or P-256: require low-s in
  `signet.chain` verification (the `prev-sig` link), or keep roots Ed25519.
- P-256 on bb: which C library (the one looked at earlier) or BouncyCastle
  through a JVM subprocess.
- Two-signer envelopes for key bindings, and the transitivity rule.
- Capability statements and choosing by the relying party (D15); HPKE as a
  possible box v3.
- Key cards (D16): decisions 1 to 6 made (2026-10-25). Still open: the
  dictionary's final form, the reader's rules, and box v3 with an
  ephemeral sender key.
- Stroopwafel-pdp, for cards (changes there need Frank's approval):
  self-scoped assertions admitted without trust, name bindings keeping
  their sayer, a join over multi-signed cards, and a sayer for derived
  aliases.
