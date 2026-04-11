(ns signet.sign
  "Ed25519 signing and verification for request signing.

   Low-level (bytes in, bytes out):
     (sign keypair message-bytes)        → 64-byte signature
     (verify key message-bytes sig)      → boolean

   High-level (EDN envelopes):
     (sign-edn payload)                  → signed envelope (uses default keypair)
     (sign-edn keypair payload)          → signed envelope
     (sign-edn keypair payload opts)     → with :ttl (seconds)
     (verify-edn envelope)              → {:valid? bool :message ... :signer ...}

   For capability chains with delegation/sealing, see signet.chain."
  (:require [cedn.core :as cedn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [signet.key :as key]
            #?(:clj [signet.impl.jvm :as jvm])))

;; ============================================================
;; Low-level: raw bytes
;; ============================================================

(defn sign
  "Sign message bytes with an Ed25519 keypair. Returns 64-byte signature.
   Accepts any key that contains a private Ed25519 key (keypair or private key)."
  [k message-bytes]
  (let [d (:d k)]
    (when-not d
      (throw (ex-info "Key has no private bytes (:d)" {:type (:type k)})))
    #?(:clj  (jvm/ed25519-sign d message-bytes)
       :cljs (throw (js/Error. "Not yet implemented for ClojureScript")))))

(defn verify
  "Verify an Ed25519 signature against message bytes.
   Accepts any key that contains an Ed25519 public key.
   Returns true if the signature is valid."
  [k message-bytes signature-bytes]
  (let [x (:x (if (key/signing-public-key? k) k (key/signing-public-key k)))]
    #?(:clj  (jvm/ed25519-verify x message-bytes signature-bytes)
       :cljs (throw (js/Error. "Not yet implemented for ClojureScript")))))

;; ============================================================
;; High-level: EDN signed envelopes
;; ============================================================

(defn sign-edn
  "Sign an EDN payload, producing a self-describing signed envelope.

   Arities:
     (sign-edn payload)                — uses default signing keypair
     (sign-edn keypair payload)        — explicit keypair
     (sign-edn keypair payload opts)   — with options:
       :ttl  seconds until expiration (optional)

   The envelope contains:
     :type       :signet/signed
     :envelope   {:message <payload> :signer <kid-urn> :request-id <uuidv7>
                  :expires <epoch-ms>}  ;; if :ttl given
     :signature  64-byte Ed25519 signature

   The signature covers the canonical EDN serialization (cedn) of :envelope."
  ([payload]
   (sign-edn (or (key/default-signing-keypair)
                  (key/signing-keypair))
             payload))
  ([keypair payload]
   (sign-edn keypair payload nil))
  ([keypair payload opts]
   (let [request-id (uuidv7/uuidv7)
         signer (key/kid keypair)
         envelope (cond-> {:message    payload
                           :signer     signer
                           :request-id request-id}
                   (:ttl opts) (assoc :expires (+ (uuidv7/extract-ts request-id)
                                                  (* 1000 (:ttl opts)))))
         canonical (cedn/canonical-bytes envelope)
         sig (sign keypair canonical)]
     {:type      :signet/signed
      :envelope  envelope
      :signature sig})))

(defn signed?
  "Returns true if x is a signed envelope (reusable key)."
  [x]
  (and (map? x) (= :signet/signed (:type x))))

(defn verify-edn
  "Verify a signed EDN envelope. Returns a result map:
     :valid?          boolean — signature check passed
     :message         the original payload
     :signer          kid URN of the signer
     :request-id      the UUIDv7
     :timestamp       epoch-ms extracted from UUIDv7
     :age-ms          milliseconds since signing
     :expires         epoch-ms (if set)
     :expired?        boolean (if :expires set)
     :digest          SHA-256 of canonical envelope (unique per signer+time)
     :message-digest  SHA-256 of canonical message (same across signers)"
  [signed-envelope]
  (let [{:keys [envelope signature]} signed-envelope
        {:keys [message signer request-id expires]} envelope
        ;; Look up signer's public key via kid URN
        pub-key (key/lookup signer)
        ;; Canonicalize and verify
        canonical (cedn/canonical-bytes envelope)
        valid? (and (some? pub-key)
                    (verify pub-key canonical signature))
        ;; Timestamps
        ts (uuidv7/extract-ts request-id)
        now #?(:clj  (System/currentTimeMillis)
               :cljs (.getTime (js/Date.)))]
    (cond-> {:valid?         valid?
             :message        message
             :signer         signer
             :request-id     request-id
             :timestamp      ts
             :age-ms         (- now ts)
             :digest         #?(:clj  (jvm/sha-256 canonical)
                                :cljs nil)
             :message-digest #?(:clj  (jvm/sha-256 (cedn/canonical-bytes message))
                                :cljs nil)}
      (some? expires) (assoc :expires expires
                             :expired? (> now expires)))))
