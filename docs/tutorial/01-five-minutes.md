# 1. Five minutes: sign, verify, box

Status: **draft, 2026-10-24.** Blocks marked **[works]** run as a test
(`signet.tutorial-test`); **[change]** blocks show the API we want instead
of today's, with the gap under "What this chapter found".

Alice signs a request and sends Bob an encrypted note. Bob checks that
the request comes from Alice and reads the note. Neither ever touches a
key, an algorithm name or a nonce.

In real life Alice and Bob are two processes. Here they share one, each
with their own vault, so the tutorial can run; that second vault is the
only line that exists for the tutorial's sake.

```clojure
;; [works]
(require '[signet.vault :as vault]
         '[signet.sign :as sign]
         '[signet.encryption :as box])

(vault/register-vault! :bob (vault/default-provider))   ; tutorial only: Bob's side
```

## Identities

```clojure
;; [works]
(def alice (vault/generate-signing-key!))         ; in Alice's vault (:default)
(def bob   (vault/generate-signing-key! :bob))    ; in Bob's
```

`alice` is a **handle**: a reference to a key that stays in the vault. It
prints as

```
#signet.vault.KeyHandle{:type :signet/key-handle
                        :kid "urn:signet:pk:ed25519:LqnNVatM…"
                        :vault :default}
```

and it is safe to print, log or send: it contains nothing secret. Its
`:kid` is the key's public name. That is what Alice gives Bob, and what
Bob gives Alice:

```clojure
;; [works]
(def alice-kid (:kid alice))
(def bob-kid   (:kid bob))

(.startsWith alice-kid "urn:signet:pk:ed25519:")
;; => true
```

The kid names its algorithm and carries the public key itself, so
knowing the kid is enough to verify Alice's signatures and to encrypt to
her. Nothing else needs to be exchanged.

## Sign and verify

Alice signs a request (any EDN value), valid for five minutes:

```clojure
;; [works]
(def signed (sign/sign-edn alice {:op :read :path "/reports"} {:ttl 300}))
```

Bob checks it, _expecting Alice_:

```clojure
;; [works]
(sign/verify-edn signed {:signer alice-kid})
;; => {:valid? true :verified? true :message {:op :read :path "/reports"}}
```

- **valid**: well-formed, the signature checks out under the key the
  envelope names, not expired. Anyone's envelope can be valid.
- **verified**: valid, _and_ signed by the identity Bob expected.

The same envelope, expecting someone else:

```clojure
;; [works]
(sign/verify-edn signed {:signer bob-kid})
;; => {:valid? false :verified? false :error :unexpected-signer}
```

`verify-edn` never throws on bad input; it answers with `:valid? false`
and an `:error`. Whether Alice may _read /reports_ is a third question
(authorization), and not signet's: that is policy (stroopwafel).

## Encrypt to someone

The API we want: Alice encrypts to Bob's kid.

```clojure
;; [change]
(def boxed (box/box alice bob-kid (.getBytes "hi bob" "UTF-8")))
```

Today `box` needs Bob's public key as a record, which the kid gives:

```clojure
;; [works]
(def boxed (box/box alice (vault/lookup bob-kid) (.getBytes "hi bob" "UTF-8")))
```

Bob opens it with whatever key his vault holds for it, expecting Alice:

```clojure
;; [works]
(def opened (box/unbox :bob boxed {:from alice-kid}))
opened
;; => {:valid? true :verified? true}

(= alice-kid (:from opened))
;; => true

(String. ^bytes (:plaintext opened) "UTF-8")
;; => "hi bob"
```

`:bob` names Bob's vault: `unbox` finds the key the box was sent to. The
box is bound to both parties: it can't be redirected to someone else or
reflected back to Alice.

## What you didn't see

- **No key bytes.** Alice's and Bob's private keys never left their vaults
  (guarded memory, with libsodium).
- **No algorithms.** Ed25519 for signatures, X25519 for the key agreement
  (from the same identity), ChaCha20-Poly1305 under a fresh key per box: all chosen by
  signet.
- **No nonces, salts or encodings.** The box and the envelope are EDN maps
  that describe themselves.
- **Only two kinds of name**: a handle for yourself, a kid for anyone else.

## What this chapter found

Written against signet 0.11.0-SNAPSHOT (2026-10-24); each item feeds a
decision in the outline.

- **F1. `box` to a kid fails badly.** `(box/box alice bob-kid …)` throws
  `IllegalArgumentException: No method in multimethod
  '-encryption-public-key' for dispatch value: null`: not an `ex-info`,
  and it doesn't say what was wrong. The fix is small (look the kid up
  inside `box`, as `unbox`'s `:from` already accepts kids); that is D2.
  Independently of D2, a wrong argument should give an `ex-info` that
  names it.
- **F2. Unknown options are ignored.** `(sign-edn alice x {:ttl-ms 60000})`
  signs _without_ expiry and says nothing; a typo removes a security
  property. Proposal: reject unknown option keys (fail closed). New
  decision D13.
- **F3. Bytes in, bytes out.** `sign-edn` takes an EDN value, `box` takes
  bytes and returns `:plaintext` bytes. `.getBytes` and `String.` are JVM
  interop and differ on cljs. Proposal: `box`/`unbox` for EDN values (as
  `sign-edn` does), bytes as the lower layer. New decision D14.
- **F4. Kids in the clear.** A box carries `:from` and `:to` kids by
  default, readable by anyone who sees it. Convenient (`unbox` finds the
  key), but it shows who talks to whom. `{:from? false :to? false}` hides
  them. Is "visible by default" the right default? Question for D14.
- **F5. Units.** `:ttl` is in seconds; `:now` and `:expires` are epoch
  milliseconds. Minor; worth one convention.
- **F6. The name says less than the key does.** `generate-signing-key!`
  makes a key that also receives boxes and runs Noise sessions. The
  tutorial calls it an identity; that is D1.
