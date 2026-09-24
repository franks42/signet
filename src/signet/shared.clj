(ns signet.shared
  "Shared symmetric keys from a key exchange, kept in the vault
   (docs/07-secret-handles-design.md, \"Shared symmetric keys\", decisions
   14 and 16).

     (def h (shared-key! my-handle their-public-key {:context \"app/v1\"}))
     (seal h plaintext)          → EDN map (per-message salt, directional key, key commitment)
     (seal h plaintext {:aad x}) ; x: any CEDN-P value, authenticated, travels in the clear
     (open h sealed)             → {:valid? … :plaintext … :aad …}; never throws
     (mac h msg)                 → 32-byte tag
     (verify-mac? h msg tag)     → boolean; never throws

   Both parties derive the same key and the same kid from their own key and
   the other's public key: no message is exchanged. Construction:

     root   = HKDF-SHA-256(X25519(mine, theirs), salt = none,
                           info = \"signet/shared/v1/root\" ‖ cedn(context)
                                  ‖ both X25519 public keys, sorted)
     kid    = HMAC(root, \"signet/shared/v1/kid\" ‖ 0x01)
              (= HKDF-Expand(root, that label, 32)), as urn:signet:shared:…
     k_msg  = HKDF(root, salt = 24 random bytes,
                   info = \"signet/shared/v1/seal\" ‖ sender_x ‖ recipient_x)
     commit = HMAC(k_msg, \"signet/shared/v1/commit\")
     ct     = ChaCha20-Poly1305(k_msg, nonce 0^96, plaintext, aad = cedn(header))

   The root key stays in the vault; under the :sodium provider every secret
   above (root, k_msg, the MAC key) is a nacljc secret and never reaches the
   heap. Only holders can compute the kid, so it does not reveal who talks
   to whom.

   Limits, stated plainly:
   - A MAC is not a signature: both parties hold the key, so a tag proves
     the message came from one of the two, not which one to a third party.
     For that, use signet.sign.
   - No forward secrecy: the key lives as long as both static keys. If
     either leaks, everything under this key is exposed. Use
     signet.session when that matters.
   - Stateless: each message has its own random 24-byte salt. The caller
     never handles a nonce."
  (:require [cedn.core :as cedn]
            [signet.encoding :as enc]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.vault :as vault]))

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))

(defn- concat-bytes ^bytes [& arrays]
  (let [out (byte-array (reduce + (map #(alength ^bytes %) arrays)))]
    (reduce (fn [off ^bytes a]
              (System/arraycopy a 0 out off (alength a))
              (+ off (alength a)))
            0 arrays)
    out))

(defn- x25519-pub ^bytes [k] (:x (key/encryption-public-key k)))

(defn- sorted-pair [^bytes a ^bytes b]
  (if (neg? (compare (enc/bytes->hex a) (enc/bytes->hex b))) [a b] [b a]))

(def ^:private zero-nonce (byte-array 12))

;; ============================================================
;; Establishing a shared key
;; ============================================================

(defn shared-key!
  "Derive the shared key between my-handle (a vault handle for an X25519 or
   Ed25519 key) and their-public (their public key or kid) for :context
   (any CEDN-P value, default nil), and keep it in my-handle's vault.
   Returns its handle, whose kid (urn:signet:shared:…) both parties compute
   identically. Calling it again returns an equal handle.
   Impure: reads and writes the vault.
   Throws ex-info {:type ::unknown-peer} if their-public is a kid that
   cannot be resolved; the vault's errors for my-handle."
  ([my-handle their-public] (shared-key! my-handle their-public nil))
  ([my-handle their-public {:keys [context]}]
   (let [their (if (string? their-public)
                 (or (vault/lookup (:vault my-handle) their-public)
                     (throw (ex-info "Cannot resolve the peer's kid" {:type ::unknown-peer :kid their-public})))
                 their-public)
         my-x    (x25519-pub (vault/public-key my-handle))
         their-x (x25519-pub their)
         [a b]   (sorted-pair my-x their-x)
         info    (concat-bytes (utf8 "signet/shared/v1/root") (cedn/canonical-bytes context) a b)
         shared  (vault/x25519-dh my-handle their-x)
         root    (try (impl/hkdf-sha-256 shared (byte-array 0) info 32)
                      (finally (impl/destroy-material! shared)))
         kid-bs  (impl/hmac-sha-256 root (concat-bytes (utf8 "signet/shared/v1/kid") (byte-array [1])))
         kid     (str "urn:signet:shared:" (enc/bytes->base64url kid-bs))]
     (vault/adopt-shared! (:vault my-handle) kid root
                          {:my-x my-x :their-x their-x :context context
                           :mine (:kid my-handle) :peer (key/kid their)}))))

(defn- meta! [h]
  (or (vault/shared-meta h)
      (throw (ex-info "Not a shared key handle" {:type ::not-a-shared-key :kid (:kid h)}))))

(defn- message-key
  "The one-message key for direction sender-x → recipient-x, salted with
   nonce, derived from root inside the call."
  [h ^bytes nonce ^bytes sender-x ^bytes recipient-x]
  (vault/with-material
    h #(impl/hkdf-sha-256 % nonce
                          (concat-bytes (utf8 "signet/shared/v1/seal") sender-x recipient-x) 32)))

(defn- commitment ^bytes [k] (impl/hmac-sha-256 k (utf8 "signet/shared/v1/commit")))

(defn- mac-key [h ^bytes sender-x ^bytes recipient-x]
  (vault/with-material
    h #(impl/hkdf-sha-256 % (byte-array 0)
                          (concat-bytes (utf8 "signet/shared/v1/mac") sender-x recipient-x) 32)))

;; ============================================================
;; seal / open
;; ============================================================

(def ^:private header-slots #{:type :v :kid :nonce :commit :aad})

(defn seal
  "Encrypt plaintext bytes under shared key h, from me to the peer. Returns
   an EDN map {:type :signet/sealed :v 1 :kid … :nonce … :commit … :aad? :ct …}.
   opts: :aad, caller context (any CEDN-P value): authenticated, NOT secret.
   Impure: draws a random nonce and reads the vault.
   Throws ex-info {:type ::not-a-shared-key}, or the vault's errors."
  ([h plaintext] (seal h plaintext nil))
  ([h plaintext opts]
   (let [{:keys [my-x their-x]} (meta! h)
         nonce  (impl/random-bytes 24)
         k      (message-key h nonce my-x their-x)]
     (try
       (let [header (cond-> {:type :signet/sealed :v 1 :kid (:kid h) :nonce nonce
                             :commit (commitment k)}
                      (contains? opts :aad) (assoc :aad (:aad opts)))
             ct     (impl/chacha20-poly1305-encrypt k zero-nonce plaintext (cedn/canonical-bytes header))]
         (assoc header :ct ct))
       (finally (impl/destroy-material! k))))))

(defn- shape-error [sealed]
  (cond
    (not (map? sealed))                                   :malformed
    (not= :signet/sealed (:type sealed))                  :not-sealed
    (not= 1 (:v sealed))                                  :unsupported-version
    (seq (remove (conj header-slots :ct) (keys sealed)))  :unknown-slot
    (not (string? (:kid sealed)))                         :bad-kid
    (not (and (bytes? (:nonce sealed)) (= 24 (alength ^bytes (:nonce sealed))))) :bad-nonce
    (not (and (bytes? (:commit sealed)) (= 32 (alength ^bytes (:commit sealed))))) :bad-commit
    (not (and (bytes? (:ct sealed)) (<= 16 (alength ^bytes (:ct sealed)))))     :bad-ciphertext))

(defn open
  "Open a value made by seal with the same shared key, sent by the peer.
   Never throws: {:valid? false :error <reason>} for anything wrong.
   opts: :aad, expected caller context (must equal the :aad slot).
   Result: {:valid? :plaintext :aad :error}.
   Impure: reads the vault."
  ([h sealed] (open h sealed nil))
  ([h sealed opts]
   (try
     (if-let [err (shape-error sealed)]
       {:valid? false :error err}
       (let [{:keys [my-x their-x]} (meta! h)]
         (cond
           (not= (:kid h) (:kid sealed)) {:valid? false :error :wrong-key}
           :else
           (let [k (message-key h (:nonce sealed) their-x my-x)]
             (try
               (if-not (java.security.MessageDigest/isEqual (commitment k) (:commit sealed))
                 {:valid? false :error :commitment-mismatch}
                 (let [pt (try (impl/chacha20-poly1305-decrypt k zero-nonce (:ct sealed)
                                                               (cedn/canonical-bytes (dissoc sealed :ct)))
                               (catch Exception _ nil))
                       aad-ok? (or (not (contains? opts :aad))
                                   (and (contains? sealed :aad)
                                        (= (cedn/canonical-str (:aad opts)) (cedn/canonical-str (:aad sealed)))))]
                   (cond
                     (nil? pt)     {:valid? false :error :authentication-failed}
                     (not aad-ok?) {:valid? false :error :aad-mismatch :aad (:aad sealed)}
                     :else         {:valid? true :plaintext pt :aad (:aad sealed)})))
               (finally (impl/destroy-material! k)))))))
     (catch Exception e
       {:valid? false :error :malformed :message (ex-message e)}))))

;; ============================================================
;; MAC
;; ============================================================

(defn mac
  "HMAC-SHA-256 tag (32 bytes) of message bytes under shared key h, from me
   to the peer (the MAC key is directional). Authenticates between the two
   parties only: it is not a signature. Impure: reads the vault."
  [h message]
  (let [{:keys [my-x their-x]} (meta! h)
        k (mac-key h my-x their-x)]
    (try (impl/hmac-sha-256 k message)
         (finally (impl/destroy-material! k)))))

(defn verify-mac?
  "Is tag the peer's MAC of message under shared key h? Constant-time
   comparison. Never throws: false for anything malformed.
   Impure: reads the vault."
  [h message tag]
  (try
    (let [{:keys [my-x their-x]} (meta! h)
          k (mac-key h their-x my-x)]
      (try (boolean (and (bytes? tag)
                         (java.security.MessageDigest/isEqual (impl/hmac-sha-256 k message) tag)))
           (finally (impl/destroy-material! k))))
    (catch Exception _ false)))
