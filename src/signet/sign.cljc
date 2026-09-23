(ns signet.sign
  "Signing and verification for request signing. Supports both Ed25519
   and secp256k1 ECDSA, dispatched on the key's :crv.

   Low-level (bytes in, bytes out):
     (sign keypair message-bytes)        → 64-byte signature
                                           (Ed25519 = raw 64; secp256k1 = raw r||s)
     (verify key message-bytes sig)      → boolean
                                           (secp256k1 verify auto-detects DER vs raw)

   High-level (EDN envelopes):
     (sign-edn payload)                  → signed envelope (uses default keypair)
     (sign-edn keypair payload)          → signed envelope
     (sign-edn keypair payload opts)     → with :ttl (seconds)
     (verify-edn envelope)              → {:valid? bool :message ... :signer ...}

   secp256k1 paths are BouncyCastle-backed and JVM-only (BC isn't in
   bb's SCI class allowlist). This namespace stays bb-friendly by
   lazy-resolving the secp256k1 impl via requiring-resolve only when
   needed, and wrapping the failure case in a clear error.

   For capability chains with delegation/sealing, see signet.chain."
  (:require [cedn.core :as cedn]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [signet.key :as key]
            #?(:clj [signet.impl :as impl])))

;; ============================================================
;; Low-level: raw bytes — dispatch on (:crv k)
;; ============================================================

#?(:clj
   (defn- secp256k1-fn
     "Lazy-resolve a function from signet.impl.jvm-secp256k1. Yields a
      clear error on bb (where BC isn't loadable) instead of the raw
      ClassNotFoundException."
     [sym]
     (try
       (requiring-resolve sym)
       (catch Throwable t
         (throw (ex-info "secp256k1 requires BouncyCastle on the JVM. BC isn't loadable on bb (SCI class allowlist); use the JVM Clojure orchestrator, or shell out to clojure -M from a bb task."
                         {:symbol sym
                          :runtime (or (System/getProperty "babashka.version") :jvm)}
                         t))))))

(defn sign
  "Sign message bytes with a signing keypair. Returns a 64-byte signature
   (raw 64 for Ed25519; raw r||s for secp256k1 ECDSA).
   Dispatches on (:crv k); accepts any key that contains a private key."
  [k message-bytes]
  (let [d (:d k)]
    (when-not d
      (throw (ex-info "Key has no private bytes (:d)" {:type (:type k)})))
    (case (:crv k)
      :Ed25519
      #?(:clj  (impl/ed25519-sign d message-bytes)
         :cljs (throw (js/Error. "Not yet implemented for ClojureScript")))

      :secp256k1
      #?(:clj  ((secp256k1-fn 'signet.impl.jvm-secp256k1/secp256k1-sign) d message-bytes)
         :cljs (throw (js/Error. "secp256k1 not yet implemented for ClojureScript")))

      (throw (ex-info "Unsupported signing curve" {:crv (:crv k) :type (:type k)})))))

(defn verify
  "Verify a signature against message bytes. Returns true if valid.
   Dispatches on (:crv k); accepts any key that contains a public key.
   For secp256k1, the signature may be raw 64-byte r||s OR DER —
   auto-detected on input."
  [k message-bytes signature-bytes]
  (let [pub (key/as-public-key k) ; pure: verifying never registers keys
        x (:x pub)]
    (case (:crv pub)
      :Ed25519
      #?(:clj  (impl/ed25519-verify x message-bytes signature-bytes)
         :cljs (throw (js/Error. "Not yet implemented for ClojureScript")))

      :secp256k1
      #?(:clj  ((secp256k1-fn 'signet.impl.jvm-secp256k1/secp256k1-verify)
                x message-bytes signature-bytes)
         :cljs (throw (js/Error. "secp256k1 not yet implemented for ClojureScript")))

      (throw (ex-info "Unsupported signing curve" {:crv (:crv pub) :type (:type pub)})))))

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

(defn- expected-kid?
  "Does kid satisfy the caller's expectation: a kid string or a set of them?"
  [expected kid]
  (if (set? expected) (contains? expected kid) (= expected kid)))

(defn verify-edn
  "Check a signed EDN envelope. Never throws: malformed input yields
   {:valid? false :error <reason>}.

   Terms (see also signet.chain/verify):
     :valid?           well-formed, the signature checks out under the key
                       named in :signer, and not expired. Self-consistency
                       only — a stranger's envelope can be valid.
     :verified?        present only when opts has :signer: valid AND the
                       signer is the expected identity. With :signer given,
                       :valid? also requires it.
     authorization     whether that signer may do this — not signet's job
                       (a policy decision point, e.g. stroopwafel's).

   opts (optional):
     :signer  expected signer: a kid URN string, or a set of acceptable kids
     :now     epoch-ms to judge expiry against. Without it this function is
              impure: it reads the system clock.

   Result keys: :valid? :signature-valid? :verified? (with :signer)
   :message :signer :request-id :timestamp :age-ms :expires :expired?
   :digest (SHA-256 of canonical envelope, unique per signer+time)
   :message-digest (SHA-256 of canonical message, same across signers)
   :error (when not valid)."
  ([signed-envelope] (verify-edn signed-envelope nil))
  ([signed-envelope {expected :signer now :now}]
   (let [invalid (fn [reason & [extra]] (merge {:valid? false :error reason} extra))
         {:keys [envelope signature]} (when (map? signed-envelope) signed-envelope)
         {:keys [message signer request-id expires]} (when (map? envelope) envelope)]
     (cond
       (not (map? envelope))            (invalid :malformed-envelope)
       (not (bytes? signature))         (invalid :missing-signature)
       (not (uuidv7/uuidv7? request-id)) (invalid :bad-request-id)
       (and (some? expires) (not (int? expires))) (invalid :bad-expires)
       :else
       (let [pub-key   (key/lookup signer)
             canonical (try (cedn/canonical-bytes envelope)
                            (catch #?(:clj Exception :cljs :default) _ nil))]
         (cond
           (nil? pub-key)   (invalid :unknown-signer {:signer signer})
           (nil? canonical) (invalid :not-canonicalizable {:signer signer})
           :else
           (let [sig-ok?  (boolean (try (verify pub-key canonical signature)
                                        (catch #?(:clj Exception :cljs :default) _ false)))
                 ts       (uuidv7/extract-ts request-id)
                 now      (or now #?(:clj  (System/currentTimeMillis)
                                     :cljs (.getTime (js/Date.))))
                 expired? (and (some? expires) (> now expires))
                 verified (when (some? expected)
                            (and sig-ok? (not expired?) (expected-kid? expected signer)))
                 valid?   (and sig-ok? (not expired?) (if (some? expected) verified true))]
             (cond-> {:valid?           valid?
                      :signature-valid? sig-ok?
                      :message          message
                      :signer           signer
                      :request-id       request-id
                      :timestamp        ts
                      :age-ms           (- now ts)
                      :digest           #?(:clj  (impl/sha-256 canonical)
                                           :cljs nil)
                      :message-digest   #?(:clj  (try (impl/sha-256 (cedn/canonical-bytes message))
                                                      (catch Exception _ nil))
                                           :cljs nil)}
               (some? expected) (assoc :verified? verified)
               (some? expires)  (assoc :expires expires :expired? expired?)
               (not valid?)     (assoc :error (cond (not sig-ok?) :bad-signature
                                                    expired?      :expired
                                                    :else         :unexpected-signer))))))))))
