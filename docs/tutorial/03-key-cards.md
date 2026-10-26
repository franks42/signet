# 3. Key cards: who I am, and what I accept

Status: **draft, 2026-10-25.** **[works]** blocks run as a test
(`signet.tutorial-test`). **[new]** blocks are the API we want: design
fiction, decided in docs/14 ("Key cards", decisions 1–6), not built.

In chapter 1, Alice gave Bob her kid, and Bob encrypted to it. That worked
because both of them use signet's defaults: Ed25519 for signing, X25519
for key agreement, box v2. Neither had to say so. That stops working as
soon as Alice has a second key (a P-256 key for an X.509 world, a
secp256k1 key for a chain), or Bob can only verify ES256, or one of them
supports a newer box. A bare kid names one key. It doesn't say what the
key is for, which other keys belong with it, or what its holder accepts.

A **key card** says that. It is an EDN map with `:type :signet/key-card`
that lists an identity's keys with their purposes, the formats the holder
accepts and the signatures it can verify, and how long all that is valid.
It is signed by every signing key it names. Alice gives Bob her card
instead of her kid. The kid stays the reference; the card is how it
travels.

**What a card is not:** a statement of trust. A valid card proves that
whoever made it holds its keys. Whether this is _the_ Alice, and what she
may do, is decided elsewhere: by how Bob got the card, by certificates,
by policy (chapter 5, stroopwafel). Keep that in mind throughout.

```clojure
;; [works]
(require '[signet.vault :as vault]
         '[signet.sign :as sign]
         '[signet.key :as key]
         '[signet.encryption :as box])

(vault/register-vault! :bob (vault/default-provider))   ; tutorial only: Bob's side

(def alice (vault/generate-signing-key!))
(def bob   (vault/generate-signing-key! :bob))
(def alice-kid (:kid alice))
(def bob-kid   (:kid bob))
```

## Alice publishes her card

The API we want: one call makes the card from what Alice's identity holds,
and signs it with every signing key on it.

```clojure
;; [new]
(require '[signet.card :as card])

(def alice-card (card/publish alice {:valid-for [30 :days]}))
```

Today the same card can be made by hand. Alice's identity is one Ed25519
key. Her agreement key is the X25519 key derived from it, the one box v2
already uses (chapter 1). On the card it is listed as a key of its own,
for `:agree`:

```clojure
;; [works]
(def alice-x-kid
  (key/kid (key/encryption-public-key (key/kid->public-key alice-kid))))

(.startsWith alice-x-kid "urn:signet:pk:x25519:")
;; => true

(def card
  {:type     :signet/key-card :v 1
   :keys     [{:kid alice-kid   :purposes #{:sign :certify} :profiles [:ed25519]}
              {:kid alice-x-kid :purposes #{:agree}         :accepts  [:box/v2]}]
   :verifies [:ed25519]
   :formats  {:envelope [1] :box [2]}})

(def signed-card (sign/sign-edn alice card {:ttl (* 30 24 3600)}))
```

The signed card is an ordinary signet envelope, so it can be printed,
stored, mailed or put on a web page. It contains nothing secret.

What the fields mean (the full dictionary, and where each field comes
from, is in docs/14):

| Field       | Says                                                                                      |
| ----------- | ----------------------------------------------------------------------------------------- |
| `:keys`     | the identity's keys, each with what it is for                                             |
| `:purposes` | `:sign`, `:certify` (signs cards and bindings), `:agree` (key agreement), `:authenticate` |
| `:profiles` | the signature formats a key produces (`:ed25519`, `:p256/x509`, `:secp256k1/cosmos`)      |
| `:accepts`  | the encryption formats a key can open, in Alice's order of preference                     |
| `:verifies` | the signature formats Alice can check                                                     |
| `:formats`  | the envelope and box versions Alice speaks                                                |

## Bob reads it

```clojure
;; [new]
(def alice-read (card/read alice-card))
(:valid? alice-read)      ;; => true
(:card alice-read)        ;; the card map
(:proof alice-read)       ;; {"urn:signet:pk:x25519:…" :derived}, see below
```

Today, Bob verifies the envelope. He passes `:signer` if he already knows
Alice's kid (from a fingerprint, or from someone he trusts):

```clojure
;; [works]
(def checked (sign/verify-edn signed-card {:signer alice-kid}))
checked
;; => {:valid? true :verified? true}

(= card (:message checked))
;; => true
```

Then he checks what the envelope alone doesn't tell him. Is the `:agree`
key really Alice's? It is derived from her signing key, and the
derivation uses public keys only, so Bob recomputes it, just as he would
recompute a kid:

```clojure
;; [works]
(def alice-agree
  (->> (:keys (:message checked))
       (filter #(contains? (:purposes %) :agree))
       first))

(= (:kid alice-agree)
   (key/kid (key/encryption-public-key (key/kid->public-key (:signer checked)))))
;; => true
```

`card/read` does this for every key and reports a **proof level** per
agreement key. The reader computes the level; the card can't claim it:

- `:derived`: recomputed from a signing key on the card, as above;
- `:signed`: the key pair signed the card itself (P-256 and secp256k1 key
  pairs can, Ed25519→X25519 doesn't need to);
- `:asserted`: listed and covered by the card's other signatures, but not
  proven. Accepted by default; Bob's policy can require more.

A changed card is no longer valid. Here Mallory swaps Alice's agreement
key for her own:

```clojure
;; [works]
(def mallory   (vault/generate-signing-key!))
(def forged    (assoc-in signed-card [:envelope :message :keys 1 :kid]
                         (key/kid (key/encryption-public-key
                                   (key/kid->public-key (:kid mallory))))))

(:valid? (sign/verify-edn forged))
;; => false
```

An outsider can't add a key to a card without its signing keys. A wrong
encryption key on a valid card comes from the holder's side: a mistake,
or a compromised system that issues cards. The proof levels make those
cases visible.

## Bob encrypts to Alice, by her card

The API we want: Bob boxes to the card. signet picks the key with
`:agree`, and the format by _Bob's_ order of preference among those the
card accepts, never Alice's order, and never below Bob's floor:

```clojure
;; [new]
(def boxed (box/box bob alice-card (.getBytes "hi alice" "UTF-8")))
```

Today Bob names the key himself. He takes the `:agree` kid from the card:

```clojure
;; [works]
(def boxed (box/box bob (vault/lookup (:kid alice-agree)) (.getBytes "hi alice" "UTF-8")))

(= (:kid alice-agree) (:to boxed))
;; => true
```

Alice opens it. Her vault holds only her Ed25519 key, and finds the
X25519 key the box was sent to through the same derivation:

```clojure
;; [works]
(def opened (box/unbox :default boxed {:from bob-kid}))
opened
;; => {:valid? true :verified? true}

(String. ^bytes (:plaintext opened) "UTF-8")
;; => "hi alice"
```

## When the card has more than one key

Alice later adds a P-256 key, for a relying party that speaks only
X.509-style ECDSA and HPKE on P-256. Her new card replaces the old one:

```clojure
;; [new]
(def alice-card-2
  (card/publish alice {:add        [(vault/generate-key! {:alg :p256 :purposes #{:sign :agree}})]
                       :supersedes alice-card
                       :valid-for  [30 :days]}))

(:keys (:card (card/read alice-card-2)))
;; => [{:kid "urn:signet:pk:ed25519:…" :purposes #{:sign :certify} :profiles [:ed25519]}
;;     {:kid "urn:signet:pk:x25519:…"  :purposes #{:agree} :accepts [:box/v2]}
;;     {:kid "urn:signet:pk:p256:…"    :purposes #{:sign :agree}
;;      :profiles [:p256/x509] :accepts [:hpke/p256-sha256-aes128gcm]}]
```

- **Every signing key signs the card.** Ed25519 signs as before, and the
  P-256 key signs the same card bytes. That makes the card the binding
  between Alice's keys (docs/14, "One identity, several keys"): a
  relying party that trusts either key sees one principal.
- **`:supersedes`** names the digest of the old card, and the old root key
  signs the new one, so a reader can follow the chain of cards.
- **`:next`** (not shown) commits to the hash of Alice's next root key, so
  a thief of today's key can't take the identity over, and a lost key can
  be succeeded.

Carol, who verifies only ES256 and opens only HPKE on P-256, now gets a
P-256 signature from Alice and can receive a box from her. Bob is
unaffected: his order of preference still picks box v2.

```clojure
;; [new]
(box/choose bob-policy alice-card-2 :encrypt)
;; => {:kid "urn:signet:pk:x25519:…" :format :box/v2 :proof :derived}

(box/choose carol-policy alice-card-2 :encrypt)
;; => {:kid "urn:signet:pk:p256:…" :format :hpke/p256-sha256-aes128gcm :proof :signed}
```

## Stronger than a card: a session

A box is accepted by the sender alone: Bob encrypts to the key on the
card, and nothing proves that Alice holds it at that moment. A Noise
session does prove it. Each side's handshake only succeeds with the
private half of its static key, so a session to an `:asserted` key either
proves it or fails, and the session is forward-secret on top. When that
matters, use a session (chapter 6) instead of a box. Noise defines 25519
and 448 only, so for P-256 the stronger option is a `:signed` card.

Box v3 (an ephemeral sender key with static authentication, HPKE's auth
mode) is planned: a later compromise of the _sender's_ key will no longer
open past boxes. A later compromise of the _recipient's_ key still will.
That is true of any message that can be sent while the recipient is
offline, and only sessions or one-time keys avoid it (docs/14,
"Decisions").

## A card is a set of statements

To a relying party's policy, a verified card is a list of statements by
its keys: "K says my purposes are …", "K says I accept …", "K1 says K2 is
the same entity", together with a statement by K2 saying the same. In
stroopwafel's terms each is an assertion with a sayer and a validity
period:

```clojure
;; [new]
(card/->assertions (card/read alice-card))
;; => [["urn:signet:pk:ed25519:…" 1792886400000 1792886400000 1795478400000
;;      :key-purposes #uuid "…" "urn:signet:pk:ed25519:…" #{:sign :certify}]
;;     ["urn:signet:pk:ed25519:…" … :accepts #uuid "…" "urn:signet:pk:x25519:…" [:box/v2]]
;;     …]
```

These statements stay dormant until the relying party's own trust facts
(said by `:self`) activate them. That is chapter 5.

## What you didn't see

- **No trust decision.** Bob learned what Alice's keys are for and what
  she accepts, and that she holds them. Whether to believe it is Alice is
  his policy's question.
- **No algorithm choice by Alice for Bob.** Alice lists; Bob chooses by
  his own order and floor.
- **No key bytes.** A card holds kids, and kids hold public keys.

## What this chapter found

Written against signet 0.11.0-SNAPSHOT (2026-10-25).

- **C1. No card API.** Making and reading a card is all by hand: a map,
  `sign-edn`, `verify-edn`, and a filter over `:keys`. Proposal:
  `signet.card` with `publish`, `read` (verify, check `:type` and `:v`,
  compute proof levels, apply the reader's rules from docs/14) and
  `->assertions`. (G13)
- **C2. A signed card looks like any signed map.** `verify-edn` checks the
  signature, not that the message is a card. `card/read` must check
  `:type :signet/key-card` and `:v`, and reject unknown `:critical` keys.
- **C3. Deriving the agreement kid takes three calls from two
  namespaces** (`key/kid`, `key/encryption-public-key`,
  `key/kid->public-key`). Proposal: one function, for example
  `key/agreement-kid`, also used by `card/read`.
- **C4. Box to the derived kid works end to end** (verified above): `box`
  addresses it, and `unbox` finds Alice's Ed25519 entry for it. Nothing to
  change; the card can name that kid safely.
- **C5. One signer per envelope.** A card signed by several keys is
  several envelopes over the same card bytes, joined on the message
  digest (TODO W5). Fine for the Ed25519-only card above; the P-256 card
  needs it.
- **C6. Validity is `:ttl` in seconds** (chapter 1, F5). The card wants an
  explicit `:not-before`/`:not-after`, and the reader its own maximum.
- **C7. No P-256 in signet yet** (G6). The P-256 parts of this chapter
  are fiction until a P-256 provider exists.
