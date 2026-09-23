# box v2 — self-describing, directional, nonce-safe

Status: **implemented** in `signet.encryption` (PR #1, merged to main
2026-09-23; build 0.7.0-SNAPSHOT), with decisions settled the same day (see
"Decisions"). **v2 replaces v1 entirely:** signet is its own
ecosystem, so there is no v1 reader or writer to keep.

## Background

`box` descends from NaCl's `crypto_box` (Bernstein, Lange, Schwabe, around
2008), which libsodium (Frank Denis, around 2013) carries forward. In NaCl's
design the ciphertext is only the 16-byte tag plus the encrypted message.
The sender's public key, the recipient's keypair and the 24-byte nonce are
all left to the surrounding protocol. libsodium's sealed box
(`crypto_box_seal`) embeds only the sender's *ephemeral* public key.

signet's box v1 wire format is `nonce(12) ‖ ChaCha20-Poly1305(k, nonce,
pt, aad)`, with `k = HKDF(X25519(sender, recipient), info = "signet/box/v1")`.
It has three problems:

1. **Keys are communicated out of band.** The receiver must already know
   who sent the box and which of its own keypairs it is for, or guess.
   Every protocol that uses box has to standardise how those values travel.
   That pushes the work up a layer and **leaks the simple "box"
   abstraction**.
2. **One key serves both directions (review finding 7).** `k` depends only
   on the unordered pair of keys, so A→B and B→A share it. A message can be
   reflected back to its sender and decrypts as if the peer had sent it.
3. **Random 96-bit nonces under one long-lived key.** A random nonce is
   safe up to about 2^32 messages per key pair. After that, collisions,
   and with them nonce reuse, become a real risk.

## Goals

- **A self-contained box.** It carries what the receiver needs to process
  it: the nonce always, and optionally the sender's and recipient's kids.
  "Receiver processing becomes much easier and less error-prone."
- **Reuse signet's kid URN** (`urn:signet:pk:x25519:<base64url>`). A
  Curve25519 public key is 32 bytes, so the kid *is* the key. A kid slot
  needs no registry lookup, and resolving it registers nothing (see
  `key/lookup`).
- **Optional slots, on by default.** The default is the easy path: both
  kids are included. Some protocols have one obvious receiver and key, so
  the kid adds nothing. Others want unlinkability: a kid on the wire tells
  observers who is talking to whom. For those, either slot can be omitted.
  Omitting a slot changes only what is *transmitted*, never what is
  *authenticated* (see "Binding").
- **Ed25519 and X25519 kids** are both accepted in the slots. The same
  usability argument holds for signet's Ed25519 identities, which are
  converted to X25519 internally, as `box` already does.
- **Directional keys**, closing finding 7.
- **Nonce-safe at any volume.** Random nonces with no practical message
  limit, handled entirely inside `box`/`unbox`. The caller never sees or
  supplies a nonce ("take the gun away").
- **The same bytes on both backends** (JCA and libsodium), verified by the
  parity check.

## Slots are hints; trust is a separate question

An embedded sender kid is **a claim, not a credential**. Anyone can box a
message to you with their own key and put their own kid in the slot. It
decrypts fine, and says it came from Mallory. So, in signet's vocabulary:

- **valid:** the box decrypts and authenticates under the named keys;
- **verified:** valid *and* the sender is the identity the caller expected
  (`unbox … {:from expected-kid-or-set}` gives `:verified?`, exactly like
  `verify-edn`'s `:signer`);
- **authorized:** policy. That is a PDP's job, not box's.

The sender slot helps the receiver *find* the right key; it must never
*decide* trust. The recipient slot helps a receiver with several keypairs
pick the right one; a missing or wrong one simply fails to decrypt.

## Binding: what is authenticated even when not transmitted

The key derivation always binds **both** public keys, in direction order:

```
shared = X25519(sender_sk, recipient_pk)          ; same value both ways
k_msg  = HKDF-SHA-256(ikm  = shared,
                      salt = nonce,               ; 24 random bytes
                      info = "signet/box/v2" ‖ sender_x25519_pk ‖ recipient_x25519_pk,
                      len  = 32)
```

The info binds the **X25519** form of each key: Ed25519 kids are converted
first. So one identity derives the same key whichever kid form (Ed25519 or
X25519) appears in a slot. The slot itself is AAD, so its form cannot be
swapped in transit.

- **Direction:** A→B uses `info = … ‖ A ‖ B` and B→A uses `… ‖ B ‖ A`, so
  their keys differ, and a reflected message fails authentication. That
  closes finding 7.
- **Per-message key:** a fresh 24-byte random salt makes every message's
  key unique. Collisions stay negligible far beyond 2^32 messages: this is
  the same idea as XChaCha20's HChaCha20 subkey (192-bit nonce), built from
  HKDF, which both backends already have. ChaCha20-Poly1305 can then use an
  all-zero 96-bit nonce, since each key encrypts exactly one message.
- **The header is AAD.** The version and any transmitted kids are
  authenticated, so swapping, adding or removing a slot breaks the tag.
  Their canonical form comes from cedn.
- **Omitted kids are still bound.** They are in `info`, which the receiver
  reconstructs from the keys it uses. Omission only changes the wire, not
  what was checked.

Alternatives considered:

- **XChaCha20-Poly1305** (192-bit nonce): libsodium only. JCA has no
  XChaCha or HChaCha20, so JCA would need a hand-written HChaCha20
  cross-checked against libsodium. The HKDF-salt construction gives the
  same property on both backends with primitives already in
  `signet.impl`.
- **libsodium `crypto_kx`** (rx/tx session keys): also directional, but it
  assumes client/server roles and is libsodium-only.
- **A counter nonce:** impossible without state shared across calls, and
  box is deliberately stateless. Sessions (`signet.session`) are the
  stateful answer.

## Wire format (EDN, like the rest of signet)

```clojure
{:type  :signet/box
 :v     2
 :from  "urn:signet:pk:ed25519:…"  ; optional (default on): sender kid, Ed25519 or X25519
 :to    "urn:signet:pk:x25519:…"   ; optional (default on): recipient kid, Ed25519 or X25519
 :aad   {:request-id #uuid "…"}    ; optional: caller context, any CEDN-P EDN value
 :nonce #bytes "…"                 ; required: 24 random bytes (the HKDF salt)
 :ct    #bytes "…"}                ; ChaCha20-Poly1305(k_msg, 0^96, pt, aad) incl. 16-byte tag
```

`aad = cedn-bytes(header)`, where `header` is every field except `:ct`, in
canonical form. The caller's context lives **inside** the header as the
optional `:aad` slot, so it is authenticated with everything else. Since
the header is canonical EDN, `:aad` can be any EDN value, not just bytes.
Two consequences:

- `:aad` **travels in the clear**: it is authenticated, not secret.
- The receiver should **check** it, not just read it. `unbox` takes an
  expected value (`{:aad expected}`) and treats a mismatch as invalid, just
  as `:from` works for the sender. Without an expectation, `unbox` returns
  the value for the caller to inspect.

Size overhead versus v1: about 24 bytes of nonce plus about 60 bytes per
kid included, plus the EDN framing. As canonical EDN *text*, cedn writes
`#bytes` in hex, so `:nonce` and `:ct` take twice their byte size. That is
negligible for signet's typical messages (commands, tokens, small
payloads), but a real cost for large ones. A compact binary transport
framing could be added later without changing the cryptography: the AAD
stays `cedn-bytes(header)`.

## API sketch

```clojure
(box   sender-kp recipient-pub plaintext)            ; default: include :from and :to
(box   sender-kp recipient-pub plaintext {:from? false :to? false :aad edn-value})
(unbox recipient-kp-or-keys boxed)                   ; resolves keys from slots when present
(unbox recipient-kp-or-keys boxed {:from expected-kid-or-set :aad expected-edn-value})
;; => {:valid? … :verified? (with :from) :plaintext … :from kid :aad … :error …}
```

- The receiver's keypair comes from the argument. If the argument is a set
  of keypairs, or the key store, it is chosen by the `:to` slot. With no
  `:to`, each candidate is tried; that is fine for the "one obvious key"
  case.
- The sender's key comes from the `:from` slot, or from the caller when
  the slot is omitted.
- Like `verify-edn`, `unbox` never throws on malformed input.
- **Nonces never appear in the API.** Ephemerals do not appear either, if
  a v2 seal is added.
- **No v1.** `box`/`unbox` read and write only v2. v1's raw
  `nonce ‖ ct` bytes are rejected as malformed (`:valid? false`). The `:v`
  field is kept so a future v3 can be told apart.

## Seal (anonymous sender), later

The same format, with the sender slot carrying the **ephemeral** public
key (e.g. `:epk`), created and wiped inside `seal`, never registered and
never exposed. `info` binds `epk ‖ recipient_pk`. A seal has no `:from`
identity by definition, so it can be valid but never "verified as" anyone.

## Test plan

- Known-answer vectors: fixed keys and nonce giving exact bytes, identical
  on the JCA and libsodium backends (parity).
- **Kid forms:** a box addressed with Ed25519 kids and one with X25519 kids
  for the same identities both unbox. Changing a slot's form in transit
  fails (AAD).
- **`:aad`:** any EDN value round-trips. A mismatch against the expected
  value, or a missing slot when one is expected, is invalid.
- **Reflection:** a message A→B fails to `unbox` as B→A, both with and
  without kid slots. It must fail today against v1 (failing-first).
- **Tampering:** changing, adding or removing `:from`, `:to`, `:v` or
  `:nonce`, or the `:ct` bytes, fails authentication.
- **Omitted slots:** unbox still works when the keys come from arguments,
  and binding still holds (an omitted-but-wrong key fails).
- **Trust:** a stranger's box is valid but not verified with `:from`; a
  wrong expected sender gives `:verified? false`.
- **Robustness:** every malformed input gives `:valid? false`, never a
  throw. Resolving kids registers nothing in the store.
- **Nonce uniqueness:** 10^6 boxes, all nonces distinct.

## Implementation notes

- `signet.encryption/box` and `unbox`, 14 tests in `encryption_test.clj`.
  All failed against v1 first. v1 demonstrably allowed reflection: Alice
  accepted her own "transfer 100 to bob" as if sent by Bob.
- **The enforcement bites (checked by injection):**
  - Making the key undirected (sorting the two keys in info) fails
    `reflection-fails`. That required adding the *slot-less* reflection
    case: with slots, header binding alone already rejects a reflected box,
    which masked the missing direction binding.
  - Dropping the header from the AAD fails the tampering and kid-form
    tests.
- Spec conformance: a test rebuilds `k` from the formula above using raw
  primitives and decrypts `box`'s output. Run under both backends, it is
  also a parity check.
- Ed25519 → X25519 conversion uses the pure `key/as-encryption-public-key`
  and `key/as-encryption-private-key`: box and unbox register nothing.
- The DH output and message key are wiped after use.

## Decisions (2026-09-23)

1. **Kid slots default to on.** The easy path is the default; omit
   `:from`/`:to` for unlinkable or single-key protocols.
2. **v1 is dropped.** No v1 reader or writer: signet lives in its own
   bubble, so there are no external v1 peers to support.
3. **Caller AAD goes inside the header** as the optional `:aad` slot (any
   EDN value; authenticated, visible on the wire, checked against
   `unbox`'s expectation).
4. **Ed25519 kids are allowed in the slots,** for the same usability
   reasons as X25519. Key derivation binds the X25519 forms, so either kid
   form derives the same key.
