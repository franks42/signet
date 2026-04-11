(ns signet.chain
  "Cryptographic block chains for capability/bearer tokens.


   Developer API — only block content goes in, all key plumbing is internal:

     (extend {:facts ...})              — create chain (uses default signing keypair as root)
     (extend root-kp {:facts ...})      — create chain with explicit root key
     (extend token {:checks ...})       — add attenuating block to existing chain
     (close token {:checks ...})        — add final block + seal (no more extensions)
     (close token)                      — seal without adding a block
     (verify token)                     — verify chain integrity + signatures

   The developer never touches ephemeral keys, next-key fields, prev-sig linking,
   or signatures. Each block is a signed envelope (sign/sign-edn) under the hood.

   Chain structure:
     {:type   :signet/chain
      :root   <kid URN of root authority>
      :blocks [<signed-envelope-0> <signed-envelope-1> ...]
      :proof  <ephemeral-sk (open) or seal-signature (sealed)>}

   Each block's :message contains:
     {:data     <developer's content — opaque EDN>
      :next-key <kid URN of next block's signer>
      :prev-sig <previous block's signature, or nil for block 0>}

   Security properties:
     - Blocks are cryptographically chained (prev-sig links)
     - Each block's signer must match previous block's next-key
     - Block 0's signer must be the root authority
     - Sealed tokens cannot be extended (ephemeral key is gone)
     - Content can only be added, never removed or reordered"
  (:refer-clojure :exclude [extend])
  (:require [cedn.core :as cedn]
            [signet.key :as key]
            [signet.sign :as sign]
            #?(:clj [signet.impl.jvm :as jvm])))

;; ============================================================
;; Internal: block creation helpers
;; ============================================================

(defn- make-ephemeral-keypair
  "Generate an ephemeral Ed25519 keypair for chain linking.
   Only the PUBLIC key is registered in the key store — the private key
   stays internal to the chain and is never registered."
  []
  #?(:clj  (let [[pub-bytes seed-bytes] (jvm/generate-ed25519-keypair)
                  ;; Register only the public key so verifiers can look it up
                  pub (key/register! (key/->Ed25519PublicKey
                                      :signet/ed25519-public-key :Ed25519 pub-bytes))
                  ;; Build a keypair record for signing, but do NOT register it
                  kp (key/->Ed25519KeyPair
                       :signet/ed25519-keypair :Ed25519 pub-bytes seed-bytes)]
              kp)
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defn- make-block
  "Create a signed block (a signed envelope) for the chain.

   Parameters:
     signing-key  — the key to sign this block with (root-kp or ephemeral-kp)
     content      — the developer's data (opaque EDN)
     next-key-kid — kid URN of the ephemeral key for the NEXT block
     prev-sig     — signature bytes from the previous block (nil for block 0)

   The block's :message wraps the developer's content with chain metadata:
     {:data     content        — what the developer provided
      :next-key next-key-kid   — links to next block's signer
      :prev-sig prev-sig}      — links to previous block's signature

   Returns a signed envelope (from sign/sign-edn)."
  [signing-key content next-key-kid prev-sig]
  (sign/sign-edn signing-key
                  {:data     content
                   :next-key next-key-kid
                   :prev-sig prev-sig}))

;; ============================================================
;; Internal: chain creation and extension
;; ============================================================

(defn- create-chain
  "Create a new chain with block 0, signed by the root authority key.

   The root key is the trust anchor — verifiers must know this key.
   An ephemeral keypair is generated for the next potential block.
   The ephemeral private key becomes the chain's 'proof' — it allows
   the token holder to extend the chain.

   Returns: {:type :signet/chain :root <kid> :blocks [block-0] :proof <eph-sk>}"
  [root-kp content]
  (let [;; Generate ephemeral keypair for the next block's signer
        ;; This keypair links block 0 to whoever extends the chain
        eph-kp (make-ephemeral-keypair)

        ;; Build and sign block 0 with the root authority key
        ;; prev-sig is nil because this is the first block
        block-0 (make-block root-kp
                            content
                            (key/kid eph-kp)  ;; next block must be signed by this key
                            nil)]             ;; no previous block
    {:type   :signet/chain
     :root   (key/kid root-kp)
     :blocks [block-0]
     :proof  (:d eph-kp)}))  ;; ephemeral private key = ability to extend

(defn- extend-chain
  "Add a new block to an existing chain, signed by the current proof.

   The proof (ephemeral private key) from the token is used to sign the
   new block. A fresh ephemeral keypair is generated for the next potential
   block. The old proof is consumed and discarded.

   The new block includes:
     - Developer's content in :data
     - prev-sig linking to the previous block's signature (chain integrity)
     - next-key pointing to the new ephemeral public key

   Returns: updated token with the new block appended and a fresh proof."
  [token content]
  (let [;; Get the previous block's signature — this links blocks together
        ;; Any attempt to remove or reorder blocks would break this chain
        last-block (peek (:blocks token))
        prev-sig   (:signature last-block)

        ;; Reconstruct the ephemeral keypair from the proof
        ;; We need the public key (from last block's next-key) and
        ;; the private key (from the proof field)
        last-next-key (get-in last-block [:envelope :message :next-key])
        eph-pub (key/kid->public-key last-next-key)
        eph-kp (key/->Ed25519KeyPair :signet/ed25519-keypair :Ed25519
                                     (:x eph-pub) (:proof token))

        ;; Generate a fresh ephemeral keypair for the NEXT block
        next-eph-kp (make-ephemeral-keypair)

        ;; Build and sign the new block with the current ephemeral key
        new-block (make-block eph-kp
                              content
                              (key/kid next-eph-kp)  ;; next block's signer
                              prev-sig)]              ;; links to previous block
    (assoc token
           :blocks (conj (:blocks token) new-block)
           :proof  (:d next-eph-kp))))  ;; fresh proof for next extension

;; ============================================================
;; Public API: predicates
;; ============================================================

(defn chain?
  "Returns true if x is a chain token (open or sealed)."
  [x]
  (and (map? x) (= :signet/chain (:type x))))

(defn sealed?
  "Returns true if the chain is sealed (no further extensions possible)."
  [token]
  (and (chain? token)
       (map? (:proof token))
       (:sealed (:proof token))))

(defn open?
  "Returns true if the chain is open (can be extended)."
  [token]
  (and (chain? token)
       (not (sealed? token))))

;; ============================================================
;; Public API: extend
;; ============================================================

(defn extend
  "Add a block to a chain. If no chain exists, creates one.

   Arities:
     (extend content)            — create new chain, root = default signing keypair
     (extend root-kp content)    — create new chain with explicit root key
     (extend token content)      — add block to existing chain

   The first argument is dispatched by type:
     nil / absent        → create chain with default signing keypair
     Ed25519KeyPair      → create chain with this key as root authority
     :signet/chain token → extend existing chain

   Content is opaque EDN — signet.chain doesn't interpret it.
   Stroopwafel or other consumers give it meaning (facts, checks, rules).

   Returns an open token: {:type :signet/chain :blocks [...] :proof <eph-sk>}"
  ([content]
   ;; No token, no explicit key → use default signing keypair as root
   (let [root-kp (key/default-signing-keypair)]
     (when-not root-kp
       (throw (ex-info
                "No default signing keypair. Create or import one first."
                {:hint "Call (key/signing-keypair) or import from SSH"})))
     (create-chain root-kp content)))
  ([token-or-key content]
   (cond
     ;; It's a token → extend the chain
     (= :signet/chain (:type token-or-key))
     (do (when (sealed? token-or-key)
           (throw (ex-info "Cannot extend a sealed chain" {})))
         (extend-chain token-or-key content))

     ;; It's a keypair → create a new chain with this root key
     (key/signing-keypair? token-or-key)
     (create-chain token-or-key content)

     :else
     (throw (ex-info "First argument must be a token or signing keypair"
                     {:type (:type token-or-key)})))))

;; ============================================================
;; Public API: close (seal)
;; ============================================================

(defn close
  "Seal a chain, preventing further extensions.

   Arities:
     (close token)          — seal without adding a block
     (close token content)  — add a final block, then seal

   Sealing works by signing the last block's signature with the
   current proof (ephemeral private key), then discarding the key.
   The proof field changes from a private key to a signature.
   After sealing, no one can extend the chain — the key is gone.

   Returns a sealed token: {:type :signet/chain :blocks [...] :proof {:sealed ...}}"
  ([token]
   (when (sealed? token)
     (throw (ex-info "Chain is already sealed" {})))
   (let [;; Get the last block's signature — this is what we seal
         last-block (peek (:blocks token))
         last-sig   (:signature last-block)

         ;; Get the ephemeral public key from last block's next-key
         ;; The proof must correspond to this key
         last-next-key (get-in last-block [:envelope :message :next-key])
         eph-pub (key/kid->public-key last-next-key)

         ;; Build ephemeral keypair from proof + public key
         eph-kp (key/->Ed25519KeyPair :signet/ed25519-keypair :Ed25519
                                      (:x eph-pub) (:proof token))

         ;; Sign the last block's signature with the ephemeral key
         ;; This proves we had the key, without revealing it
         seal-sig (sign/sign eph-kp last-sig)]

     ;; Return sealed token — proof is now a signature, not a private key
     ;; The ephemeral private key goes out of scope here — gone forever
     (assoc token
            :proof {:sealed    true
                    :signature seal-sig})))
  ([token content]
   ;; Add the final block, then seal
   (-> (extend-chain token content)
       (close))))


;; ============================================================
;; Public API: third-party blocks
;; ============================================================

(defn third-party-request
  "Create a request for a third-party block.

   The token holder calls this to get the binding info needed by an
   external party (e.g., an IdP) to sign a block bound to this
   specific chain instance.

   The third party needs the previous block's signature to bind
   their signed content to this chain — preventing replay of their
   block into a different chain.

   Throws if the token is sealed.

   Returns:
     {:type     :signet/third-party-request
      :prev-sig <bytes — signature of the last block>}"
  [token]
  (when (sealed? token)
    (throw (ex-info "Cannot create third-party request from a sealed chain" {})))
  {:type     :signet/third-party-request
   :prev-sig (:signature (peek (:blocks token)))})

(defn create-third-party-block
  "Create a signed third-party block (called by the external party).

   The third party signs their content bound to a specific chain
   instance via `prev-sig` from the request. This prevents the
   block from being replayed into a different chain.

   Arguments:
     - `request`  : from `third-party-request` — contains :prev-sig
     - `content`  : opaque EDN (the third party's assertions)
     - `tp-key`   : the third party's signing keypair

   Returns:
     {:type          :signet/third-party-block
      :data          <content>
      :external-sig  <signature over canonical {data + prev-sig}>
      :external-key  <kid URN of the third party>}"
  [request content tp-key]
  (let [;; The payload that gets signed: content + chain binding
        signable {:data     content
                  :prev-sig (:prev-sig request)}
        canonical #?(:clj  (cedn/canonical-bytes signable)
                     :cljs (throw (js/Error. "Not yet implemented")))
        ext-sig  (sign/sign tp-key canonical)]
    {:type          :signet/third-party-block
     :data          content
     :external-sig  ext-sig
     :external-key  (key/kid tp-key)}))

(defn extend-third-party
  "Append a third-party block to a chain.

   The token holder calls this after receiving the signed block from
   the third party. The block is wrapped in the chain's ephemeral
   key chain like any other block, but also carries the external
   signature and key for independent verification.

   Throws if the token is sealed.

   Arguments:
     - `token`    : open chain
     - `tp-block` : from `create-third-party-block`

   Returns: updated token with the third-party block appended."
  [token tp-block]
  (when (sealed? token)
    (throw (ex-info "Cannot extend a sealed chain" {})))
  (let [last-block (peek (:blocks token))
        prev-sig   (:signature last-block)

        ;; Reconstruct ephemeral keypair from proof + last block's next-key
        last-next-key (get-in last-block [:envelope :message :next-key])
        eph-pub (key/kid->public-key last-next-key)
        eph-kp (key/->Ed25519KeyPair :signet/ed25519-keypair :Ed25519
                                     (:x eph-pub) (:proof token))

        ;; Generate fresh ephemeral keypair for the next block
        next-eph-kp (make-ephemeral-keypair)

        ;; Build block content: developer's data + third-party metadata
        block-content {:data         (:data tp-block)
                       :next-key     (key/kid next-eph-kp)
                       :prev-sig     prev-sig
                       :external-sig (:external-sig tp-block)
                       :external-key (:external-key tp-block)}

        ;; Sign with the ephemeral key (chain integrity)
        new-block (sign/sign-edn eph-kp block-content)]
    (assoc token
           :blocks (conj (:blocks token) new-block)
           :proof  (:d next-eph-kp))))

;; ============================================================
;; Public API: verify
;; ============================================================

(defn verify
  "Verify a chain's integrity and all signatures.

   Checks:
     1. Block 0's signer matches the root authority
     2. Each block's signature is valid (via sign/verify-edn)
     3. Each block's prev-sig matches the previous block's signature
     4. Each block's signer matches the previous block's next-key
     5. Third-party blocks: external signature verified against external key
     6. If sealed: the seal signature verifies against the last block's next-key
     7. If open: the proof corresponds to the last block's next-key

   Returns:
     {:valid?   boolean
      :sealed?  boolean
      :root     kid URN of root authority
      :blocks   vector of each block's verification result (from sign/verify-edn)
      :error    error message if invalid (optional)}"
  [token]
  (let [blocks (:blocks token)
        root   (:root token)

        ;; Verify each block's signature and check chain links
        block-results
        (reduce
          (fn [{:keys [results prev-sig prev-next-key error] :as acc} block]
            (if error
              ;; Short-circuit on first error
              acc
              (let [;; Verify this block's signature using sign/verify-edn
                    result (sign/verify-edn block)

                    ;; Extract chain metadata from the block's message
                    msg         (:message result)
                    block-next  (:next-key msg)
                    block-prev  (:prev-sig msg)
                    signer      (:signer result)

                    ;; Block 0: signer must be root authority
                    ;; Block N: signer must match previous block's next-key
                    expected-signer (or prev-next-key root)

                    ;; Check chain integrity
                    sig-valid?   (:valid? result)
                    signer-ok?   (= signer expected-signer)
                    prev-sig-ok? (if prev-sig
                                   ;; Compare prev-sig in this block with
                                   ;; actual signature of previous block
                                   (java.util.Arrays/equals
                                     ^bytes block-prev
                                     ^bytes prev-sig)
                                   ;; Block 0: prev-sig should be nil
                                   (nil? block-prev))]
                (cond
                  (not sig-valid?)
                  (assoc acc :error (str "Invalid signature on block " (count results)))

                  (not signer-ok?)
                  (assoc acc :error (str "Signer mismatch on block " (count results)
                                        ": expected " expected-signer
                                        ", got " signer))

                  (not prev-sig-ok?)
                  (assoc acc :error (str "prev-sig mismatch on block " (count results)))

                  :else
                  ;; Check external signature if this is a third-party block
                  (let [ext-sig (:external-sig msg)
                        ext-ok? (if ext-sig
                                  #?(:clj
                                     (let [ext-pub (key/kid->public-key (:external-key msg))
                                           ext-payload {:data     (:data msg)
                                                        :prev-sig prev-sig}
                                           ext-canonical (cedn/canonical-bytes ext-payload)]
                                       (sign/verify ext-pub ext-canonical ext-sig))
                                     :cljs false)
                                  true)]
                    (if-not ext-ok?
                      (assoc acc :error (str "External signature invalid on block " (count results)))
                      {:results       (conj results result)
                       :prev-sig      (:signature block)
                       :prev-next-key block-next
                       :error         nil}))))))
          {:results [] :prev-sig nil :prev-next-key nil :error nil}
          blocks)

        ;; If blocks verified, check the proof (seal or open)
        proof-valid?
        (when-not (:error block-results)
          (let [last-block    (peek blocks)
                last-next-key (get-in last-block [:envelope :message :next-key])
                last-pub      (key/kid->public-key last-next-key)]
            (if (sealed? token)
              ;; Sealed: verify the seal signature against last block's next-key
              (let [seal-sig (get-in token [:proof :signature])
                    last-sig (:signature last-block)]
                (sign/verify last-pub last-sig seal-sig))
              ;; Open: verify the proof (eph-sk) corresponds to last block's next-key
              ;; Check by deriving public key from proof and comparing
              #?(:clj
                 (let [derived-pub (jvm/ed25519-seed->public-key (:proof token))]
                   (java.util.Arrays/equals
                     ^bytes (:x last-pub)
                     ^bytes derived-pub))
                 :cljs false))))]

    (if-let [error (:error block-results)]
      ;; Chain verification failed at some block
      {:valid?  false
       :sealed? (sealed? token)
       :root    root
       :blocks  (:results block-results)
       :error   error}
      ;; All blocks verified — check proof
      {:valid?  (boolean proof-valid?)
       :sealed? (sealed? token)
       :root    root
       :blocks  (mapv :message (:results block-results))
       :error   (when-not proof-valid? "Invalid proof")})))
