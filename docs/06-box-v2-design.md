# box v2 — self-describing, directional, nonce-safe

Status: **design note, not implemented** (2026-09-23). Supersedes nothing;
box v1 (`signet.encryption/box`) stays readable.

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
- **Optional slots.** Some protocols have one obvious receiver and key, so
  the kid adds nothing. Others want unlinkability: a kid on the wire tells
  observers who is talking to whom. So both kid slots can be omitted.
  Omitting a slot changes only what is *transmitted*, never what is
  *authenticated* (see "Binding").
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
                      info = "signet/box/v2" ‖ sender_pk ‖ recipient_pk,
                      len  = 32)
```

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
 :from  "urn:signet:pk:x25519:…"   ; optional: sender kid
 :to    "urn:signet:pk:x25519:…"   ; optional: recipient kid
 :nonce #bytes "…"                 ; required: 24 random bytes (the HKDF salt)
 :ct    #bytes "…"}                ; ChaCha20-Poly1305(k_msg, 0^96, pt, aad) incl. 16-byte tag
```

`aad = cedn-bytes({:type :v :from? :to? :nonce})`: every field except
`:ct`, in canonical form. Caller AAD, if given (`{:aad bytes}`), is
appended under a separate key so it cannot collide with the header.

Size overhead versus v1: about 24 bytes of nonce plus about 60 bytes per
kid included, plus the EDN framing. Negligible for the intended uses.

## API sketch

```clojure
(box   sender-kp recipient-pub plaintext)            ; defaults: include :from and :to
(box   sender-kp recipient-pub plaintext {:from? false :to? false :aad bytes})
(unbox recipient-kp-or-keys boxed)                   ; resolves keys from slots when present
(unbox recipient-kp-or-keys boxed {:from expected-kid-or-set :aad bytes})
;; => {:valid? … :verified? (with :from) :plaintext … :from kid :error …}
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
- **v1 compatibility:** `unbox` dispatches on the input. Raw bytes are
  v1; a `{:type :signet/box :v 2}` map is v2. `box` writes v2; a v1 writer
  is kept only for peers that cannot read v2.

## Seal (anonymous sender), later

The same format, with the sender slot carrying the **ephemeral** public
key (e.g. `:epk`), created and wiped inside `seal`, never registered and
never exposed. `info` binds `epk ‖ recipient_pk`. A seal has no `:from`
identity by definition, so it can be valid but never "verified as" anyone.

## Test plan

- Known-answer vectors: fixed keys and nonce giving exact bytes, identical
  on the JCA and libsodium backends (parity).
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

## Open questions

1. Should the kid slots default to on (ease) or off (privacy)? This note
   proposes on, with `:from? false` / `:to? false` for unlinkable or
   single-key protocols.
2. Does a v1 writer stay available, or is v1 read-only after v2 ships?
3. Should the caller's `:aad` sit inside the cedn header map (simpler) or
   be appended as separate bytes (keeps the header shape fixed)?
4. Should Ed25519 identity kids be allowed in the slots (converted to X25519
   internally, as `box` does today), or only `x25519` kids on the wire?
