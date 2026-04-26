# Noise KK Session Design (signet.session)

This doc captures the design rationale and Noise-protocol mechanics for
`signet.session`, the forward-secret session layer that landed in
signet 0.6.0. It is written so a reader who has not previously studied
Noise can follow the implementation with the spec
([noiseprotocol.org/noise.html](https://noiseprotocol.org/noise.html))
open in a second window.

## Why a session layer at all

Through signet 0.5.0 the encryption story was `signet.encryption/box`
and `unbox` — sender-authenticated AEAD via static-static X25519 DH.
That gives **authenticated encryption** between two long-term
identities, but it does not give **forward secrecy**: the X25519 DH
output is a pure function of the two long-term keys, so if either
private key leaks at any point in the future, every past ciphertext
becomes readable. For one-shot capability tokens or per-message
authenticated payloads that's an acceptable trade. For a *session* —
multiple correlated messages between the same parties — it is not.

`signet.session` adds forward secrecy by layering ephemeral key
exchange on top of the long-term identities: each session generates
fresh ephemeral X25519 keypairs, derives session keys from
ephemeral-ephemeral DH, and discards the ephemerals at session
end. Even total compromise of both parties' long-term keys after the
fact reveals nothing about traffic that was protected by ephemeral
DH outputs that no longer exist.

Authentication still rides on the long-term keys (see "What KK
authenticates" below). The session layer's job is *forward secrecy*
on top of authentication, not authentication on top of nothing.

## Why Noise

We could roll our own ephemeral-DH protocol — generate ephemerals,
sign them with long-term keys, exchange, derive session keys with
HKDF, AEAD with ChaCha20-Poly1305 — and the result would be a proto-
Noise variant. Two reasons we use the actual Noise spec instead:

1. **Noise is a small, sharp specification with mature analysis.**
   The framework is the work of Trevor Perrin (also of Signal). The
   spec is public, peer-reviewed, and has had over a decade of
   adversarial scrutiny. WireGuard, libssh, WhatsApp's bootstrap, and
   numerous other systems are built on it. Reinventing this primitive
   is the kind of work where the value is in *not* introducing
   subtle bugs.

2. **The framework decomposes cleanly into reusable parts.** Noise
   gives you a small algebra of handshake patterns (`KK`, `KN`, `XK`,
   `XX`, `IK`, `IX`, `NK`, `NN`, ...) parameterized over a DH group, a
   cipher, and a hash. Once you have one pattern implemented, adding
   others is local — the symmetric primitives, the message-token
   processor, and the cipher state are shared. We start with KK; if a
   future use case wants XK (asymmetric pre-knowledge of static keys)
   the additional code is small.

The concrete protocol we implement here is
**`Noise_KK_25519_ChaChaPoly_SHA256`**: KK pattern, X25519 DH,
ChaCha20-Poly1305 AEAD, SHA-256 hash. The protocol-name string —
literally that text, 32 bytes long — is mixed into the initial
transcript hash, so any deviation in the named primitives produces
incompatible sessions. This is intentional: there is no silent
algorithm negotiation in Noise.

## Why KK and not XK

A handshake pattern is named by two letters:
- The **first** describes how the **initiator's** long-term static
  key is conveyed to the responder.
- The **second** describes how the **responder's** long-term static
  key is conveyed to the initiator.

The letters are:
- `N` — None: the static key is not conveyed at all (anonymous side).
- `K` — Known: the static key is known to the peer **before** the
  handshake begins (out-of-band).
- `X` — eXchanged: the static key is **transmitted during** the
  handshake, encrypted under the early DH outputs.
- `I` — Immediate: the static key is sent in the very first message,
  before any DH has hidden it.

So `KK` means "both parties already know each other's long-term
static public keys before the handshake". `XK` means "the responder's
key is known in advance, but the initiator's is sent during the
handshake". `XX` means "neither is known in advance; both are
transmitted during the handshake".

In the mpc-multi-signature consumer that drove this work, every
party announces its long-term Ed25519 identity public key to the
orchestrator at startup (the `:party/identity` handshake added in
Stage 5b.2), and the orchestrator distributes the full
`{role pubkey-hex}` map to every party at the start of each
ceremony. So both sides of every pairwise session **already know
each other's static keys** before they exchange a single Noise
message. KK is exactly the pattern for that situation.

The practical wins of KK over XK:
- **Two messages instead of three.** XK takes three to complete
  the handshake; KK takes two. One fewer round trip means less
  ceremony-startup latency.
- **Less bandwidth.** XK has to transmit the initiator's static
  public key during the handshake (encrypted under early DH);
  KK doesn't.
- **Smaller code path.** Fewer handshake-state transitions to
  implement and test.

The cost: KK requires that you actually have the static key
distribution problem already solved out-of-band. If you don't —
e.g., a connection from an unknown client to a known server — XK
or IK is the correct pattern. This is a constraint of the
deployment, not of the spec.

## What KK authenticates and what it doesn't

After a successful KK handshake, both sides hold a session key
derived from a chain of HKDF mixings of three DH outputs:

- **`es`**: DH(initiator's ephemeral private, responder's static public)
- **`ss`**: DH(initiator's static private, responder's static public)
- **`ee`**: DH(initiator's ephemeral private, responder's ephemeral public) — first DH after responder replies
- **`se`**: DH(initiator's static private, responder's ephemeral public)

The set `{es, ss, se, ee}` is collectively called the "noise output"
for KK. Notice each of `ss`, `se`, `es` involves at least one
**static** key from each side — either as private (one side) or
public (the other side). That is what gives **mutual
authentication**: only the holder of initiator's static private
could have produced output that, mixed with responder's static
private, produces the same chain. An attacker who lacks **either**
party's static private key cannot forge a session.

The set also includes `ee`, which is **ephemeral-ephemeral**. That
is what gives **forward secrecy**: the session key chain depends on
both ephemerals, so deleting either ephemeral after the session
ends erases the only material from which the key could be
reconstructed. Long-term keys alone are not enough.

What KK does **not** give you:
- **Identity hiding for the initiator.** The initiator's static key is
  pre-shared (via `K`), so an observer who already knows that key
  can detect that party's involvement. (XK hides the initiator's
  identity from passive observers because `X` transmits the static
  encrypted; that's what makes it useful for client-to-known-server
  protocols.)
- **Post-compromise security.** Once an ephemeral leaks during the
  session, the rest of that session is readable. KK does not
  re-key automatically. If you need post-compromise security, run
  multiple sessions and rotate.
- **Transport replay protection across sessions.** The 12-byte AEAD
  nonce is a counter starting at 0 for each session direction.
  Two sessions with the same long-term keys and same first
  ephemeral would have nonce reuse — but that requires generating
  the same ephemeral twice, which is already a worse problem than
  replay. Within a session, the counter monotonically increments,
  so in-session replay is rejected.

## API shape

The session abstraction is a **pure-functional state machine**.
No mutable state, no atoms. Each operation takes a state and
returns a new state plus produced bytes (or consumes bytes and
returns plaintext). The mpc consumer can persist intermediate
state, retry on transient errors, and reason about lifecycles
without thread-safety overhead.

```clojure
(initiator local-static-kp remote-static-pub & {:keys [prologue]})
;; → handshake-state, role :initiator, message-pos 0

(responder local-static-kp remote-static-pub & {:keys [prologue]})
;; → handshake-state, role :responder, message-pos 0

(write-message state plaintext-bytes)
;; → [next-state ciphertext-bytes]
;; During handshake, ciphertext carries: ephemeral-pub bytes,
;; encrypted application payload (AEAD-tagged with the running
;; transcript). After Split(), pure transport mode:
;; ciphertext is just ChaCha20-Poly1305(send-key, nonce, plaintext, h)
;; with nonce baked into state.

(read-message state ciphertext-bytes)
;; → [next-state plaintext-bytes]
;; Inverse of write-message. Throws on AEAD authentication failure
;; (which catches both tampered ciphertext and a wrong-peer DH).

(established? state)
;; → boolean. True iff Split() has run; transport messages may flow.
```

The handshake follows the KK pattern's two-message exchange. The
initiator calls `write-message` to produce message 1; the responder
`read-message`s it, then `write-message`s message 2; the initiator
`read-message`s the reply. After that exchange, both sides'
`established?` is true, and `write-message` / `read-message` switch
silently into transport mode. Application code does not change
between handshake and transport — the same two functions handle
both phases. This mirrors the Noise spec's `WriteMessage` and
`ReadMessage` operations.

## Symmetric primitives

The Noise spec describes the handshake state as a small set of
**symmetric-state** primitives that operate on three pieces of
state:

- `ck` (chaining key, 32 bytes) — accumulates DH outputs through
  HKDF chaining. Starts equal to `h`.
- `k` (encryption key, 32 bytes; or `:empty`) — current AEAD key,
  if any. Starts `:empty` and is set by the first `MixKey`.
- `n` (nonce counter, integer) — for the AEAD; resets to 0 when
  `k` is set.
- `h` (transcript hash, 32 bytes) — running SHA-256 of every
  message exchanged so far, for AEAD AAD binding.

The four operations:

```
MixHash(data):           h ← SHA-256(h ‖ data)
MixKey(input-key-mat):   [ck, k] ← HKDF(salt=ck, ikm=input, info="", 64)
                         n ← 0
EncryptAndHash(plain):   if k = :empty:  ct ← plain
                         else:           ct ← AEAD(k, n, h, plain); n++
                         MixHash(ct);  return ct
DecryptAndHash(ct):      if k = :empty:  plain ← ct
                         else:           plain ← AEAD-decrypt(k, n, h, ct); n++
                         MixHash(ct);  return plain
Split():                 [t1, t2] ← HKDF(salt=ck, ikm="", info="", 64)
                         return cipher-state(t1), cipher-state(t2)
```

The `MixKey` HKDF call uses `ck` as the **salt**, the DH output as
the **input keying material**, and an empty `info` field. The
output is 64 bytes; first 32 become the new `ck`, last 32 become
the new `k`. This is HKDF-Expand-style chaining: each DH output
"adds entropy" to both the chaining key (which feeds future
mixings) and the immediate AEAD key (which encrypts the rest of
this message).

The transcript hash `h` is used as the AEAD's AAD (additional
authenticated data) on every encryption. That binds each AEAD
ciphertext to **the entire history of the handshake up to that
point** — an attacker who manages to substitute or reorder any
prior message will fail decryption on the next one.

## KK message processing in detail

Initial state, both sides:

```
protocol-name = "Noise_KK_25519_ChaChaPoly_SHA256" (32 bytes exactly)
h  = protocol-name (no padding needed; len = 32)
ck = h
k  = :empty
n  = 0

;; Pre-message handshake (both sides do this in the same order):
MixHash(initiator-static-public)
MixHash(responder-static-public)

;; Optional prologue (default empty bytes):
MixHash(prologue)
```

Note that pre-message processing **does not run any DHs** — it
only mixes the static public keys into the transcript hash. The
DHs happen during the messages themselves.

Message 1, initiator → responder, tokens `e, es, ss, [payload]`:

```
;; Initiator side:
generate fresh ephemeral keypair (e_priv, e_pub)
output buffer ← e_pub                       ; 32 bytes
MixHash(e_pub)                                ; "e"
MixKey(DH(e_priv, remote-static-pub))         ; "es" — sets k for first time
MixKey(DH(local-static-priv, remote-static-pub)) ; "ss"
output buffer ← output buffer ‖ EncryptAndHash(payload)
send output buffer

;; Responder side:
read 32 bytes ← e_pub (claimed)
MixHash(e_pub)
MixKey(DH(local-static-priv, e_pub))            ; "es" from responder's POV
MixKey(DH(local-static-priv, remote-static-pub)) ; "ss"
read remaining bytes ← payload-ciphertext
plaintext ← DecryptAndHash(payload-ciphertext)
```

Notice both sides compute the **same** DH outputs (DH is symmetric:
`DH(a_priv, b_pub) = DH(b_priv, a_pub)`), so `MixKey` evolves their
`ck` and `k` identically. After this message both sides have the
**same `k`**, derived from a chain that incorporated both an
ephemeral DH (`es`) and a static DH (`ss`). The first AEAD encryption
of the message-1 payload uses that `k` and is authenticated against
both initiator's ephemeral and the static-static binding.

Message 2, responder → initiator, tokens `e, ee, se, [payload]`:

A subtlety here that's easy to get wrong: in Noise's two-letter DH
tokens, the **first letter always names the *initiator's* key**, and
the **second letter always names the *responder's* key**, regardless
of who is processing the message. So `se` means DH(initiator-static,
responder-ephemeral). Since DH is symmetric, the responder (who
holds the responder-ephemeral private and the initiator-static
public) computes that as `DH(resp-eph-priv, init-static-pub)` —
which is the **responder's ephemeral** combined with the
**initiator's static**, not the other way around.

```
;; Responder side:
generate fresh ephemeral keypair (e_priv, e_pub)
output buffer ← e_pub
MixHash(e_pub)                                ; "e"
MixKey(DH(e_priv, remote-ephemeral-pub))      ; "ee" — forward secrecy comes in here
MixKey(DH(e_priv, remote-static-pub))         ; "se" — my-eph + their-static
output buffer ← output buffer ‖ EncryptAndHash(payload)
send output buffer

;; Initiator side:
read 32 bytes ← e_pub (claimed responder ephemeral)
MixHash(e_pub)
MixKey(DH(local-ephemeral-priv, e_pub))         ; "ee" — my-eph + their-eph
MixKey(DH(local-static-priv, e_pub))             ; "se" — my-static + their-eph
read remaining ← payload-ciphertext
plaintext ← DecryptAndHash(payload-ciphertext)
```

After message 2, both sides have folded **four DH outputs**
(`es, ss, ee, se`) into their chaining key. The `ee` step is what
elevates this from "static-static-with-extra-mixing" to
"forward-secret": the ephemeral private keys can now be discarded.

Both sides then call `Split()`:

```
[t1, t2] ← HKDF(salt=ck, ikm=empty, info="", 64)
;; Initiator's send cipher uses t1; recv cipher uses t2.
;; Responder's send cipher uses t2; recv cipher uses t1.
```

Each cipher state is `(key=t_i, nonce=0, increments-on-encrypt)`.
Subsequent transport messages are pure AEAD with that key, no
more `MixHash` or `MixKey` operations (the transcript hash `h`
becomes irrelevant once `Split()` has executed, though some Noise
extensions like rekey do reuse it).

## Key-format flexibility (Ed25519 inputs)

The signet.session API takes signet keypair records, not raw
X25519 byte arrays. The mpc-multi-signature consumer's long-term
identities are **Ed25519** keypairs (used for capability signing
and the share-possession binding proofs); we do not want to make
it carry a separate X25519 keypair just for transport.

Signet already solved this problem in 0.5.0: `signet.encryption/box`
auto-converts Ed25519 keypairs to X25519 via the Ed25519↔X25519
birational map (`signet.impl.jvm/ed25519-keypair->x25519-keypair`),
and `signet.key/raw-shared-secret` accepts either curve. We reuse
both. From the consumer's standpoint, the **same** Ed25519 identity
keypair feeds capability signing, share-possession proofs, and now
Noise sessions.

This is a deliberate property: one identity, multiple uses. The
crypto is sound (the X25519 derived from an Ed25519 keypair is
deterministic and curve-distinct; signature operations on the
Ed25519 form do not interfere with DH operations on the derived
X25519 form). The convenience is that there is exactly one private
key to manage per identity.

## Failure modes

The session layer raises (via `ex-info`) on:

- **AEAD authentication failure** during a handshake message read.
  Indicates either tampered ciphertext, wrong remote-static (the
  expected DH outputs don't match), or wrong ephemeral. From the
  caller's standpoint these are indistinguishable — and that's
  intentional: AEAD's correctness guarantees mean we cannot tell
  the attacker *which* part of their forgery failed. The error
  category is `:reason/aead-auth-failed`.

- **Wrong message phase.** Calling `write-message` on a handshake
  state that expects to read next, or vice versa, raises
  `:reason/wrong-message-phase`. This catches simple programming
  errors (e.g., the responder forgetting to read message 1 before
  trying to write message 2).

- **Truncated input.** A handshake message must contain at least
  the ephemeral pub (32 bytes) plus a 16-byte AEAD tag (= 48 bytes
  minimum even for empty-payload messages). Shorter inputs raise
  `:reason/handshake-message-too-short`.

The library does NOT enforce a maximum message size, a maximum
number of transport messages per session, or automatic re-keying.
Those are policy decisions for the consumer.

## Forward-secrecy boundary

Forward secrecy in Noise KK is bounded by:

1. **Both sides must actually destroy ephemerals** when the session
   ends. The library does not enforce this — it returns immutable
   state and trusts the caller to discard. For sessions whose state
   is held in memory only and goes out of scope when the session
   ends, this is automatic; for sessions persisted to disk, the
   consumer is responsible.

2. **Forward secrecy is only forward.** It protects past traffic
   against future compromise of either long-term key. It does *not*
   protect future traffic against past compromise — if either
   ephemeral leaks during the session, that session's traffic is
   exposed from that point onward. Different sessions are
   independent (fresh ephemerals each time), so a single session
   compromise does not extend.

3. **The static-key distribution channel is trust-on-first-use, or
   trust-via-some-other-mechanism.** Noise itself does not solve
   PKI. KK assumes you already have the right peer's static
   public key; how you got it is out of band. In the
   mpc-multi-signature case the orchestrator's `:identity-pubkeys`
   map is that distribution channel; the ceremony's invariants
   (every party authenticates the orchestrator, the orchestrator
   sees every party's announced pubkey at startup) are what gives
   KK the static-key-knowledge it needs.

## Scope of this release

signet 0.6.0 ships:
- `Noise_KK_25519_ChaChaPoly_SHA256` only.
- Pure-functional state machine; no atoms, no rebinding, no global
  state.
- Ed25519 keypair input via the existing birational conversion.
- JCA-only on the JVM, bb-compatible (we use the same primitives
  signet.encryption already uses: `chacha20-poly1305-{encrypt,
  decrypt}`, `hkdf-sha-256`, `sha-256`, `random-bytes`, `x25519-dh`).
- Tests for handshake roundtrip, transport roundtrip, tamper
  detection, wrong-static failure, empty payload, multi-message
  transport.

What 0.6.x or later might add:
- Other handshake patterns (XK for client-to-known-server, IK for
  zero-RTT, NN for the simplest anonymous case).
- Pre-shared key (PSK) modifiers — `Noise_KKpsk0_*` and friends —
  for an additional layer of authentication beyond static keys.
- Re-keying during long sessions (Noise has a defined `Rekey()`
  operation that can be applied to a cipher state).
- ClojureScript implementation (currently JVM-only because the
  underlying JCA primitives are).

## References

- Noise Protocol Framework specification, Trevor Perrin (rev 34
  and later): https://noiseprotocol.org/noise.html
- WireGuard whitepaper, Jason A. Donenfeld:
  https://www.wireguard.com/papers/wireguard.pdf — applied
  walkthrough of `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the
  closest large-deployment cousin to what we're building.
- `snow` (Rust): https://github.com/mcginty/snow — the most
  popular reference implementation; its test vectors are useful
  for cross-implementation validation.
- `noise-c` (C): https://github.com/rweather/noise-c — also widely
  studied; closer to the spec text in style.
