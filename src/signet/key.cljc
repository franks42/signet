(ns signet.key
  "Key generation and management for Ed25519 (signing) and X25519 (encryption),
   plus secp256k1 ECDSA (signing — for interop with Bitcoin/Ethereum/Cosmos
   wallet keys and MPC threshold-signature ceremony output).

   Keypair construction (multimethods, extensible):
     (signing-keypair)             — generate new Ed25519 keypair (default curve)
     (signing-keypair :secp256k1)  — generate new secp256k1 keypair
     (signing-keypair x d)         — Ed25519 from raw public + seed (32+32 bytes)
     (signing-keypair :secp256k1 x d) — secp256k1 from compressed pub (33) + scalar (32)
     (signing-keypair m)           — from map (EDN round-trip, JWK, SSH, etc.)

     (encryption-keypair)     — generate new X25519 keypair
     (encryption-keypair x d) — adopt existing key bytes
     (encryption-keypair m)   — from map, also accepts Ed25519 keys (cross-converts)

   Public/private key extraction (multimethods, extensible):
     (signing-public-key k)     — extract public key (curve preserved)
     (signing-private-key k)    — extract private key (curve preserved)
     (encryption-public-key k)  — X25519 public key, also cross-converts from Ed25519
     (encryption-private-key k) — X25519 private key, also cross-converts from Ed25519

   Convenience:
     (public-key k)     — same-curve public key extraction
     (private-key k)    — same-curve private key extraction
     (kid k)            — base64url key identifier

   Predicates:
     (signing-keypair? k) (signing-public-key? k) (signing-private-key? k)
       — true for any signing curve (Ed25519 or secp256k1)
     (encryption-keypair? k) (encryption-public-key? k) (encryption-private-key? k)"
  (:require [clojure.string :as str]
            [signet.encoding :as enc]
            #?(:clj [signet.impl.jvm :as jvm])))

;; -- Records

(defrecord Ed25519KeyPair [type crv x d])
(defrecord Ed25519PublicKey [type crv x])
(defrecord Ed25519PrivateKey [type crv d])

(defrecord X25519KeyPair [type crv x d])
(defrecord X25519PublicKey [type crv x])
(defrecord X25519PrivateKey [type crv d])
(defrecord X25519SharedKey [type crv k kid-a kid-b])

;; secp256k1 ECDSA — for interop with Bitcoin/Ethereum/Cosmos/MPC.
;; Public key (:x) is 33-byte compressed sec1 form (`[02|03] || x32`).
;; Private key (:d) is the 32-byte scalar.
(defrecord Secp256k1KeyPair [type crv x d])
(defrecord Secp256k1PublicKey [type crv x])
(defrecord Secp256k1PrivateKey [type crv d])

(derive Ed25519KeyPair :signet/ed25519-keypair)
(derive Ed25519PublicKey :signet/ed25519-public-key)
(derive Ed25519PrivateKey :signet/ed25519-private-key)

(derive X25519KeyPair :signet/x25519-keypair)
(derive X25519PublicKey :signet/x25519-public-key)
(derive X25519PrivateKey :signet/x25519-private-key)
(derive X25519SharedKey :signet/x25519-shared-secret)

(derive Secp256k1KeyPair :signet/secp256k1-keypair)
(derive Secp256k1PublicKey :signet/secp256k1-public-key)
(derive Secp256k1PrivateKey :signet/secp256k1-private-key)

;; Parent tags for curve-agnostic predicates.
(derive :signet/ed25519-keypair      :signet/signing-keypair)
(derive :signet/secp256k1-keypair    :signet/signing-keypair)
(derive :signet/ed25519-public-key   :signet/signing-public-key)
(derive :signet/secp256k1-public-key :signet/signing-public-key)
(derive :signet/ed25519-private-key  :signet/signing-private-key)
(derive :signet/secp256k1-private-key :signet/signing-private-key)

;; ============================================================
;; Key Store — auto-discovery of keys by kid
;; ============================================================

;; ============================================================
;; Default keys — first-one-wins unless explicitly overridden
;; ============================================================

(def ^:private default-signing-keypair* (atom nil))
(def ^:private default-encryption-keypair* (atom nil))

(defn set-default-signing-keypair!
  "Explicitly set the default signing keypair. Overrides any auto-set default."
  [kp]
  (reset! default-signing-keypair* kp))

(defn set-default-encryption-keypair!
  "Explicitly set the default encryption keypair. Overrides any auto-set default."
  [kp]
  (reset! default-encryption-keypair* kp))

(defn default-signing-keypair
  "Return the default signing keypair, or nil if none set."
  []
  @default-signing-keypair*)

(defn default-encryption-keypair
  "Return the default encryption keypair, or nil if none set."
  []
  @default-encryption-keypair*)

(defn clear-defaults!
  "Clear both default keypairs."
  []
  (reset! default-signing-keypair* nil)
  (reset! default-encryption-keypair* nil)
  nil)

(defn- auto-set-default!
  "Set as default if it's a keypair and no default exists yet (first-one-wins).
   Both Ed25519 and secp256k1 keypairs become signing-keypair candidates."
  [k]
  (case (:type k)
    :signet/ed25519-keypair
    (compare-and-set! default-signing-keypair* nil k)
    :signet/secp256k1-keypair
    (compare-and-set! default-signing-keypair* nil k)
    :signet/x25519-keypair
    (compare-and-set! default-encryption-keypair* nil k)
    nil)
  k)

;; -- URN helpers

(defn- urn-algorithm
  "Return the URN algorithm component for a key's curve."
  [crv]
  (case crv
    :Ed25519   "ed25519"
    :X25519    "x25519"
    :secp256k1 "secp256k1"))

;; ============================================================
;; Key Store — auto-discovery of keys by kid
;; ============================================================

(def default-key-store
  "Global key store: atom of {kid-string → key-record}.
   Keys are auto-registered when created or reconstructed.
   'Most info wins': keypair > private-key > public-key."
  (atom {}))

(def ^:private type-rank
  "Ranking for 'most info wins' — higher number wins."
  {:signet/ed25519-keypair       3
   :signet/ed25519-private-key   2
   :signet/ed25519-public-key    1
   :signet/x25519-keypair        3
   :signet/x25519-private-key    2
   :signet/x25519-public-key     1
   :signet/secp256k1-keypair     3
   :signet/secp256k1-private-key 2
   :signet/secp256k1-public-key  1})

(def ^:private known-key-types
  #{:signet/ed25519-keypair :signet/ed25519-public-key :signet/ed25519-private-key
    :signet/x25519-keypair :signet/x25519-public-key :signet/x25519-private-key
    :signet/secp256k1-keypair :signet/secp256k1-public-key :signet/secp256k1-private-key})

(defn register!
  "Register a key in the store. Idempotent — a keypair will not be
   overwritten by a public key for the same kid. Returns the key.

   For private-only keys, derives the public key bytes for kid
   computation when the platform supports it. secp256k1 private-only
   derivation is not yet implemented (JDK doesn't expose point
   multiplication directly); such keys register without a kid."
  ([k] (register! default-key-store k))
  ([store k]
   (when (and k (:type k) (known-key-types (:type k)))
     (let [;; Need public key bytes for kid — may need derivation for private-only keys
           x-bytes (or (:x k)
                       #?(:clj (case (:type k)
                                 :signet/ed25519-private-key   (jvm/ed25519-seed->public-key (:d k))
                                 :signet/x25519-private-key    (jvm/x25519-private->public-key (:d k))
                                 :signet/secp256k1-private-key nil ; TODO: requires EC point mul
                                 nil)
                          :cljs nil))
           alg (urn-algorithm (:crv k))
           kid-str (when (and x-bytes alg)
                     (str "urn:signet:pk:" alg ":" (enc/bytes->base64url x-bytes)))
           new-rank (get type-rank (:type k) 0)]
       (when kid-str
         (swap! store (fn [m]
                        (let [existing (get m kid-str)
                              old-rank (get type-rank (:type existing) 0)]
                          (if (> new-rank old-rank)
                            (assoc m kid-str k)
                            m)))))))
   (auto-set-default! k)
   k))

(defn lookup
  "Look up a key by kid URN string. Returns the best key record or nil.
   If not found in the store but the URN contains the public key,
   parses it and auto-registers."
  ([kid-str] (lookup default-key-store kid-str))
  ([store kid-str]
   (or (get @store kid-str)
       ;; URN is self-describing — extract public key if not in store
       (when (and (string? kid-str) (.startsWith ^String kid-str "urn:signet:pk:"))
         (let [[_ _ _ alg b64] (str/split kid-str #":")
               pub (case alg
                     "ed25519"   (->Ed25519PublicKey :signet/ed25519-public-key :Ed25519
                                                     (enc/base64url->bytes b64))
                     "x25519"    (->X25519PublicKey :signet/x25519-public-key :X25519
                                                    (enc/base64url->bytes b64))
                     "secp256k1" (->Secp256k1PublicKey :signet/secp256k1-public-key :secp256k1
                                                       (enc/base64url->bytes b64))
                     nil)]
           (when pub
             (register! store pub)
             pub))))))

(defn registered-keys
  "Return all registered keys as a seq."
  ([] (registered-keys default-key-store))
  ([store] (vals @store)))

(defn clear-key-store!
  "Remove all keys from the store and clear default keypairs."
  ([] (clear-key-store! default-key-store))
  ([store]
   (reset! store {})
   (clear-defaults!)
   nil))

(defn unregister!
  "Remove a key by kid string. Returns the removed key or nil."
  ([kid-str] (unregister! default-key-store kid-str))
  ([store kid-str]
   (let [k (get @store kid-str)]
     (swap! store dissoc kid-str)
     k)))

;; -- Predicates
;;
;; Signing predicates are curve-agnostic — true for Ed25519 OR secp256k1
;; via the :signet/signing-* parent tags. Use record-instance checks or
;; (= (:crv k) :Ed25519) when curve-specific behavior is needed.

(defn signing-keypair?      [k] (and k (isa? (:type k) :signet/signing-keypair)))
(defn signing-public-key?   [k] (and k (isa? (:type k) :signet/signing-public-key)))
(defn signing-private-key?  [k] (and k (isa? (:type k) :signet/signing-private-key)))

(defn encryption-keypair?     [k] (= (:type k) :signet/x25519-keypair))
(defn encryption-public-key?  [k] (= (:type k) :signet/x25519-public-key))
(defn encryption-private-key? [k] (= (:type k) :signet/x25519-private-key))
(defn raw-shared-secret?             [k] (= (:type k) :signet/x25519-shared-secret))

;; -- Dispatch helpers

(defn- classify-args
  "Dispatch function for keypair multimethods.
   Returns a vector for multimethod dispatch.

   A leading curve keyword (e.g. :Ed25519, :secp256k1) selects the
   curve explicitly:
     ()                    → [:generate]            (Ed25519 default)
     (:secp256k1)          → [:generate :secp256k1]
     (m)                   → [:map (:type m)]
     (x d)                 → [:from-bytes]          (Ed25519 default)
     (:secp256k1 x d)      → [:from-bytes :secp256k1]"
  [& args]
  (case (count args)
    0 [:generate]
    1 (let [a (first args)]
        (cond
          (keyword? a) [:generate a]
          (map? a)     [:map (:type a)]
          :else        (throw (ex-info "Unsupported argument type" {:arg a}))))
    2 [:from-bytes]
    3 (let [[a _ _] args]
        (if (keyword? a)
          [:from-bytes a]
          (throw (ex-info "3-arg form requires a curve keyword first" {:args args}))))
    (throw (ex-info "Too many arguments" {:count (count args)}))))

;; ============================================================
;; signing-keypair — always returns Ed25519KeyPair
;; ============================================================

(defmulti -signing-keypair classify-args)

(defn signing-keypair
  "Create a signing keypair. Defaults to Ed25519; pass :secp256k1 (or
   :Ed25519 explicit) as the leading argument to switch curves.
   Auto-registers the result in the key store.

   Arities:
     ()                  — generate a new Ed25519 keypair
     (:secp256k1)        — generate a new secp256k1 keypair
     (x d)               — Ed25519 from raw pub (32) + seed (32)
     (:secp256k1 x d)    — secp256k1 from compressed pub (33) + scalar (32)
     (m)                 — from a map, dispatched on (:type m)"
  ([] (register! (-signing-keypair)))
  ([m-or-crv] (register! (-signing-keypair m-or-crv)))
  ([x d] (register! (-signing-keypair x d)))
  ([crv x d] (register! (-signing-keypair crv x d))))

;; -- Ed25519 (default curve)

(defmethod -signing-keypair [:generate] [& _]
  #?(:clj  (let [[pub-bytes seed-bytes] (jvm/generate-ed25519-keypair)]
             (->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 pub-bytes seed-bytes))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -signing-keypair [:generate :Ed25519] [& _]
  #?(:clj  (let [[pub-bytes seed-bytes] (jvm/generate-ed25519-keypair)]
             (->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 pub-bytes seed-bytes))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -signing-keypair [:from-bytes] [& [x d]]
  (->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 x d))

(defmethod -signing-keypair [:from-bytes :Ed25519] [& [_ x d]]
  (->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 x d))

(defmethod -signing-keypair [:map :signet/ed25519-keypair] [& [m]]
  (map->Ed25519KeyPair m))

(defmethod -signing-keypair [:map :signet/ed25519-private-key] [& [m]]
  #?(:clj  (let [d (:d m)
                 x (jvm/ed25519-seed->public-key d)]
             (->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 x d))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; -- secp256k1 ECDSA
;;
;; STATUS: only verify is supported in this build. Generation throws a
;; clear not-yet-implemented (SunEC rejects secp256k1 for keygen; needs
;; BouncyCastle — see TODO in signet.impl.jvm). Constructing a record
;; from caller-supplied bytes is fine (no JCA involved).

(defmethod -signing-keypair [:generate :secp256k1] [& _]
  #?(:clj  (let [gen (try
                       (requiring-resolve 'signet.impl.jvm-secp256k1/generate-secp256k1-keypair)
                       (catch Throwable t
                         (throw (ex-info "secp256k1 keypair generation requires BouncyCastle on the JVM. BC isn't loadable on bb (SCI class allowlist); use the JVM Clojure orchestrator."
                                         {:runtime (or (System/getProperty "babashka.version") :jvm)}
                                         t))))
                 [pub-bytes priv-bytes] (gen)]
             (->Secp256k1KeyPair :signet/secp256k1-keypair :secp256k1 pub-bytes priv-bytes))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -signing-keypair [:from-bytes :secp256k1] [& [_ x d]]
  ;; Pure record construction with caller-supplied bytes — no JCA call,
  ;; works on bb and JVM regardless of provider support for keygen.
  (->Secp256k1KeyPair :signet/secp256k1-keypair :secp256k1 x d))

(defmethod -signing-keypair [:map :signet/secp256k1-keypair] [& [m]]
  (map->Secp256k1KeyPair m))

(defmethod -signing-keypair [:map :signet/secp256k1-private-key] [& [_m]]
  ;; Deriving public key from a secp256k1 private scalar requires EC
  ;; point multiplication, which JCA doesn't expose directly. For the
  ;; MPC harness use case both are always known together; if you reach
  ;; this branch you probably want to construct from (x d) directly or
  ;; pass a full keypair map.
  (throw (ex-info "secp256k1-private-only → keypair derivation not yet implemented (need EC point mul)"
                  {:hint "construct via (signing-keypair :secp256k1 x d) or pass a full keypair map"})))

;; ============================================================
;; encryption-keypair — always returns X25519KeyPair
;; ============================================================

(defmulti -encryption-keypair classify-args)

(defn encryption-keypair
  "Create an X25519 encryption keypair. Always returns an X25519KeyPair.
   Also accepts Ed25519 keys for cross-curve conversion.
   Auto-registers the result in the key store.

   Arities:
     ()      — generate a new random keypair
     (x d)   — from raw public key (32 bytes) and private key (32 bytes)
     (m)     — from a map, dispatched on (:type m)"
  ([] (register! (-encryption-keypair)))
  ([m] (register! (-encryption-keypair m)))
  ([x d] (register! (-encryption-keypair x d))))

(defmethod -encryption-keypair [:generate] [& _]
  #?(:clj  (let [[pub-bytes priv-bytes] (jvm/generate-x25519-keypair)]
             (->X25519KeyPair :signet/x25519-keypair :X25519 pub-bytes priv-bytes))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -encryption-keypair [:from-bytes] [& [x d]]
  (->X25519KeyPair :signet/x25519-keypair :X25519 x d))

(defmethod -encryption-keypair [:map :signet/x25519-keypair] [& [m]]
  (map->X25519KeyPair m))

(defmethod -encryption-keypair [:map :signet/x25519-private-key] [& [m]]
  #?(:clj  (let [d (:d m)
                 x (jvm/x25519-private->public-key d)]
             (->X25519KeyPair :signet/x25519-keypair :X25519 x d))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; Ed25519 → X25519 cross-curve conversion (keypair)
;; Public key:  u = (1 + y) / (1 - y) mod p  (birational map)
;; Private key: SHA-512(seed)[0..31] with clamping

(defmethod -encryption-keypair [:map :signet/ed25519-keypair] [& [m]]
  #?(:clj  (let [[x-pub x-priv] (jvm/ed25519-keypair->x25519-keypair (:x m) (:d m))]
             (->X25519KeyPair :signet/x25519-keypair :X25519 x-pub x-priv))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -encryption-keypair [:map :signet/ed25519-private-key] [& [m]]
  #?(:clj  (let [x-priv (jvm/ed25519-seed->x25519-private (:d m))
                 x-pub (jvm/x25519-private->public-key x-priv)]
             (->X25519KeyPair :signet/x25519-keypair :X25519 x-pub x-priv))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; ============================================================
;; signing-public-key — always returns Ed25519PublicKey
;; ============================================================

(defmulti -signing-public-key :type)

(defn signing-public-key
  "Extract or reconstruct an Ed25519 public key. Always returns Ed25519PublicKey.
   Auto-registers the result."
  [k] (register! (-signing-public-key k)))

(defmethod -signing-public-key :signet/ed25519-keypair [kp]
  (->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 (:x kp)))

(defmethod -signing-public-key :signet/ed25519-public-key [k] k)

(defmethod -signing-public-key :signet/ed25519-private-key [k]
  #?(:clj  (let [x (jvm/ed25519-seed->public-key (:d k))]
             (->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 x))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -signing-public-key :signet/secp256k1-keypair [kp]
  (->Secp256k1PublicKey :signet/secp256k1-public-key :secp256k1 (:x kp)))

(defmethod -signing-public-key :signet/secp256k1-public-key [k] k)

(defmethod -signing-public-key :signet/secp256k1-private-key [_k]
  (throw (ex-info "secp256k1-private-only → public derivation not yet implemented"
                  {:hint "supply the public key alongside the private key"})))

;; ============================================================
;; signing-private-key — always returns Ed25519PrivateKey
;; ============================================================

(defmulti -signing-private-key :type)

(defn signing-private-key
  "Extract an Ed25519 private key. Always returns Ed25519PrivateKey.
   Auto-registers the result."
  [k] (register! (-signing-private-key k)))

(defmethod -signing-private-key :signet/ed25519-keypair [kp]
  (->Ed25519PrivateKey :signet/ed25519-private-key :Ed25519 (:d kp)))

(defmethod -signing-private-key :signet/ed25519-private-key [k] k)

(defmethod -signing-private-key :signet/secp256k1-keypair [kp]
  (->Secp256k1PrivateKey :signet/secp256k1-private-key :secp256k1 (:d kp)))

(defmethod -signing-private-key :signet/secp256k1-private-key [k] k)

;; ============================================================
;; encryption-public-key — always returns X25519PublicKey
;; ============================================================

(defmulti -encryption-public-key :type)

(defn encryption-public-key
  "Extract or convert to an X25519 public key. Always returns X25519PublicKey.
   Also accepts Ed25519 keys for cross-curve conversion.
   Auto-registers the result."
  [k] (register! (-encryption-public-key k)))

(defmethod -encryption-public-key :signet/x25519-keypair [kp]
  (->X25519PublicKey :signet/x25519-public-key :X25519 (:x kp)))

(defmethod -encryption-public-key :signet/x25519-public-key [k] k)

(defmethod -encryption-public-key :signet/x25519-private-key [k]
  #?(:clj  (let [x (jvm/x25519-private->public-key (:d k))]
             (->X25519PublicKey :signet/x25519-public-key :X25519 x))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; Ed25519 → X25519 cross-curve conversion (public key)

(defmethod -encryption-public-key :signet/ed25519-keypair [kp]
  #?(:clj  (->X25519PublicKey :signet/x25519-public-key :X25519
                              (jvm/ed25519-pub->x25519-pub (:x kp)))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -encryption-public-key :signet/ed25519-public-key [k]
  #?(:clj  (->X25519PublicKey :signet/x25519-public-key :X25519
                              (jvm/ed25519-pub->x25519-pub (:x k)))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -encryption-public-key :signet/ed25519-private-key [k]
  #?(:clj  (let [x-priv (jvm/ed25519-seed->x25519-private (:d k))
                 x-pub (jvm/x25519-private->public-key x-priv)]
             (->X25519PublicKey :signet/x25519-public-key :X25519 x-pub))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; ============================================================
;; encryption-private-key — always returns X25519PrivateKey
;; ============================================================

(defmulti -encryption-private-key :type)

(defn encryption-private-key
  "Extract or convert to an X25519 private key. Always returns X25519PrivateKey.
   Also accepts Ed25519 keys for cross-curve conversion.
   Auto-registers the result."
  [k] (register! (-encryption-private-key k)))

(defmethod -encryption-private-key :signet/x25519-keypair [kp]
  (->X25519PrivateKey :signet/x25519-private-key :X25519 (:d kp)))

(defmethod -encryption-private-key :signet/x25519-private-key [k] k)

;; Ed25519 → X25519 cross-curve conversion (private key)

(defmethod -encryption-private-key :signet/ed25519-keypair [kp]
  #?(:clj  (->X25519PrivateKey :signet/x25519-private-key :X25519
                               (jvm/ed25519-seed->x25519-private (:d kp)))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmethod -encryption-private-key :signet/ed25519-private-key [k]
  #?(:clj  (->X25519PrivateKey :signet/x25519-private-key :X25519
                               (jvm/ed25519-seed->x25519-private (:d k)))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

;; ============================================================
;; Convenience: public-key, private-key (same-curve shortcuts)
;; ============================================================

(defn public-key
  "Same-curve public key extraction. Delegates to signing-public-key
   or encryption-public-key based on the key's curve."
  [k]
  (case (:crv k)
    :Ed25519   (signing-public-key k)
    :secp256k1 (signing-public-key k)
    :X25519    (encryption-public-key k)))

(defn private-key
  "Same-curve private key extraction. Delegates to signing-private-key
   or encryption-private-key based on the key's curve."
  [k]
  (case (:crv k)
    :Ed25519   (signing-private-key k)
    :secp256k1 (signing-private-key k)
    :X25519    (encryption-private-key k)))

;; ============================================================
;; kid — key identifier
;; ============================================================

(defn kid
  "Return the key identifier as a URN: urn:signet:pk:<algorithm>:<base64url-public-key>.
   Self-describing — the receiver can parse the URN to extract the algorithm
   and the public key bytes directly."
  [k]
  (let [pub (public-key k)]
    (str "urn:signet:pk:" (urn-algorithm (:crv pub)) ":" (enc/bytes->base64url (:x pub)))))

(defn kid->public-key
  "Parse a kid URN and return the public key record.
   Extracts the algorithm and public key bytes from the URN."
  [kid-str]
  (let [[_ _ _ alg b64] (str/split kid-str #":")]
    (case alg
      "ed25519"   (->Ed25519PublicKey :signet/ed25519-public-key :Ed25519
                                      (enc/base64url->bytes b64))
      "x25519"    (->X25519PublicKey :signet/x25519-public-key :X25519
                                     (enc/base64url->bytes b64))
      "secp256k1" (->Secp256k1PublicKey :signet/secp256k1-public-key :secp256k1
                                        (enc/base64url->bytes b64)))))

(defn kid->hex
  "Return the key's 32-byte public key as a lowercase hex string.
   Accepts a kid URN or any key record — for records, equivalent to
   (enc/bytes->hex (:x (public-key k))).

   NOTE: hex is a lossy representation — it drops the algorithm tag
   that the URN carries. Use only for interop with external tools
   that expect raw hex."
  [k]
  (let [pub (if (string? k) (kid->public-key k) (public-key k))]
    (enc/bytes->hex (:x pub))))

(defn hex->kid
  "Build a kid URN from a hex-encoded public key.
   Since hex carries no algorithm tag, the curve must be specified
   (default :Ed25519).

   Arities:
     (hex->kid hex)       — assumes Ed25519
     (hex->kid hex :X25519) — explicit curve

   Returns a kid URN string (and auto-registers the public key in the
   signet key store as a side effect of parsing)."
  ([hex] (hex->kid hex :Ed25519))
  ([hex crv]
   (let [pub-bytes (enc/hex->bytes hex)
         pub       (case crv
                     :Ed25519   (->Ed25519PublicKey :signet/ed25519-public-key
                                                    :Ed25519 pub-bytes)
                     :X25519    (->X25519PublicKey :signet/x25519-public-key
                                                   :X25519 pub-bytes)
                     :secp256k1 (->Secp256k1PublicKey :signet/secp256k1-public-key
                                                      :secp256k1 pub-bytes))]
     (register! pub)
     (kid pub))))

;; ============================================================
;; raw-shared-secret — X25519 Diffie-Hellman key agreement
;; ============================================================

(defn- do-raw-shared-secret
  "Perform DH given X25519 private bytes, X25519 public bytes, and both kids."
  [our-priv their-pub kid-a kid-b]
  #?(:clj  (let [k (jvm/x25519-dh our-priv their-pub)]
             (->X25519SharedKey :signet/x25519-shared-secret :X25519 k kid-a kid-b))
     :cljs  (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defmulti -raw-shared-secret
  (fn [our-key their-key]
    [(:type our-key) (:type their-key)]))

(defn raw-shared-secret
  "Compute a shared secret via X25519 Diffie-Hellman key agreement.
   Accepts any combination of Ed25519 and X25519 keys — Ed25519 keys are
   automatically cross-converted to X25519.
   Auto-registers both parties' keys in the key store.

   Returns an X25519SharedKey record with :k (32-byte shared secret),
   :kid-a (our key id), and :kid-b (their key id).

   The shared secret is symmetric:
     (raw-shared-secret alice-kp bob-pub) has the same :k as (raw-shared-secret bob-kp alice-pub)"
  [our-key their-key]
  (register! our-key)
  (register! their-key)
  (-raw-shared-secret our-key their-key))

;; X25519 × X25519

(defmethod -raw-shared-secret [:signet/x25519-keypair :signet/x25519-keypair] [our their]
  (do-raw-shared-secret (:d our) (:x their)
                        (kid our) (kid their)))

(defmethod -raw-shared-secret [:signet/x25519-keypair :signet/x25519-public-key] [our their]
  (do-raw-shared-secret (:d our) (:x their)
                        (kid our) (kid their)))

(defmethod -raw-shared-secret [:signet/x25519-private-key :signet/x25519-public-key] [our their]
  (do-raw-shared-secret (:d our) (:x their)
                        (kid our) (kid their)))

(defmethod -raw-shared-secret [:signet/x25519-private-key :signet/x25519-keypair] [our their]
  (do-raw-shared-secret (:d our) (:x their)
                        (kid our) (kid their)))

;; Cross-curve: auto-convert Ed25519 → X25519 and delegate

(defmethod -raw-shared-secret :default [our their]
  (let [our-x (cond
                (#{:signet/x25519-keypair :signet/x25519-private-key} (:type our))
                our
                (#{:signet/ed25519-keypair :signet/ed25519-private-key} (:type our))
                (encryption-keypair our)
                :else
                (throw (ex-info "First argument must contain a private key" {:type (:type our)})))
        their-x (cond
                  (#{:signet/x25519-keypair :signet/x25519-public-key} (:type their))
                  their
                  (#{:signet/ed25519-keypair :signet/ed25519-public-key
                     :signet/ed25519-private-key} (:type their))
                  (encryption-public-key their)
                  (#{:signet/x25519-private-key} (:type their))
                  (encryption-public-key their)
                  :else
                  (throw (ex-info "Second argument must contain a public key" {:type (:type their)})))]
    (do-raw-shared-secret (:d our-x) (:x their-x)
                          (kid our) (kid their))))
