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
