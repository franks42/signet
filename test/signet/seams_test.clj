(ns signet.seams-test
  "Regression tests for the seams between the vault, shared keys, key
   records and the two backends (review REVIEW.md, 2026-09-26). Each test
   names its finding; each was shown to fail before its fix."
  (:require [clojure.test :refer [deftest is use-fixtures]]
            [signet.chain :as chain]
            [signet.encoding :as enc]
            [signet.encryption :as box]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.session :as session]
            [signet.shared :as shared]
            [signet.sign :as sign]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (vault/reset-default-vault!) (f)))

(def ^:private ack {:i-understand :exposes-secret})

(def ^:private bb?
  "secp256k1 needs Bouncy Castle, which cannot load on babashka."
  (some? (System/getProperty "babashka.version")))

(defn- error-type
  "The ex-data :type f throws, :no-throw, or [:not-ex-info class]."
  [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(defn- utf8 ^bytes [s] (.getBytes ^String s "UTF-8"))

;; ---- 1. shared-key handles in box/unbox and the vault's DH ----

(deftest unbox-by-vault-id-ignores-shared-keys
  ;; The failure depended on hash-set order, so run with fresh keys.
  (dotimes [_ 20]
    (vault/reset-default-vault!)
    (let [me   (vault/generate-encryption-key!)
          peer (vault/generate-encryption-key!)
          _    (shared/shared-key! me (vault/public-key peer))]
      (is (:valid? (box/unbox :default (box/box peer (vault/public-key me) (utf8 "hi")))))
      (is (:valid? (box/unbox :default (box/box peer (vault/public-key me) (utf8 "hi") {:to? false})
                              {:from (:kid peer)}))
          "without a :to slot every candidate is tried"))))

(deftest shared-handles-are-refused-as-identity-keys
  (let [me   (vault/generate-encryption-key!)
        peer (vault/generate-encryption-key!)
        sh   (shared/shared-key! me (vault/public-key peer))]
    (is (= :signet.vault/wrong-algorithm (error-type #(vault/x25519-dh sh (byte-array 32 (byte 9))))))
    (is (= :signet.vault/wrong-algorithm (error-type #(vault/public-key sh))))
    (is (= :signet.vault/wrong-algorithm
           (error-type #(box/box sh (vault/public-key peer) (utf8 "x")))))
    (is (= :no-recipient-key (:error (box/unbox sh (box/box peer (vault/public-key me) (utf8 "x"))))))))

;; ---- 2. and 3. closing chains ----

(deftest close-with-content-refuses-a-sealed-token
  (let [sealed (chain/close (chain/extend (vault/generate-signing-key!) {:a 1}))]
    (is (= :signet.chain/sealed (error-type #(chain/close sealed {:more 2}))))))

(deftest closing-an-exported-token-destroys-the-proof-everywhere
  (let [tok      (chain/extend (vault/generate-signing-key!) {:a 1})
        proof    (:proof tok)
        exported (chain/export-token tok ack)
        seed     (:proof exported)]
    (chain/close exported)
    (is (nil? (vault/handle (:kid proof))) "the vault's copy of the proof is gone")
    (is (every? zero? seed) "the exported seed is wiped")))

;; ---- 4. invalid points: both backends refuse, with the same error ----

(defn- ed-kid [^bytes x] (str "urn:signet:pk:ed25519:" (enc/bytes->base64url x)))

(deftest invalid-ed25519-points-are-typed-errors
  (let [identity-point (let [b (byte-array 32)] (aset-byte b 0 1) b) ; y = 1
        me             (vault/generate-signing-key!)]
    (is (= :signet.impl/invalid-public-key
           (error-type #(impl/ed25519-pub->x25519-pub identity-point))))
    (is (= :signet.impl/invalid-public-key
           (error-type #(session/initiator me (ed-kid identity-point))))
        "a crafted peer kid is refused up front, on every backend")
    (is (= :signet.impl/low-order-point
           (error-type #(impl/x25519-dh (impl/random-bytes 32) (byte-array 32)))))))

;; ---- 5. one kid parser ----

(deftest kid->public-key-validates-like-lookup
  (let [short-kid (ed-kid (byte-array 5))]
    (is (nil? (key/lookup short-kid)))
    (is (= :signet.key/malformed-kid (error-type #(key/kid->public-key short-kid))))
    (is (= :signet.key/malformed-kid (error-type #(key/kid->public-key "urn:signet:pk:rsa:AAAA"))))
    (is (= :signet.key/malformed-kid (error-type #(key/kid->public-key "not a kid"))))))

;; ---- 6. sign/verify takes handles ----

(deftest verify-accepts-a-handle
  (let [h (vault/generate-signing-key!) m (utf8 "m")]
    (is (true? (sign/verify h m (sign/sign h m))))))

;; ---- 7. wrong key types at public entry points ----

(deftest wrong-key-types-are-typed-errors
  (let [me (vault/generate-signing-key!)]
    (when-not bb?
      (let [secp (key/public-key (key/signing-keypair :secp256k1))]
        (is (= :signet.session/bad-key-type (error-type #(session/initiator me secp))))
        (is (= :signet.session/bad-key-type (error-type #(session/initiator me (key/kid secp)))))))
    (is (= :signet.session/bad-key-type (error-type #(session/initiator me {:not "a key"}))))
    (is (= :signet.shared/bad-key-type (error-type #(shared/shared-key! me {:not "a key"}))))
    (is (= :signet.vault/bad-key-type (error-type #(vault/register-public-key! {:not "a key"}))))))

;; ---- 8. register! of a key it cannot index ----

(deftest register-refuses-a-key-without-a-kid
  (when-not bb?
    (let [kp (key/signing-keypair :secp256k1)
          sk (key/signing-private-key kp)]
      (is (= :signet.key/no-kid (error-type #(key/register! sk)))))))

;; ---- 9. HKDF output length ----

(deftest jca-hkdf-refuses-lengths-beyond-rfc-5869
  (let [hkdf @(requiring-resolve 'signet.impl.jvm/hkdf-sha-256)]
    (is (= 8160 (alength ^bytes (hkdf (byte-array 32) 8160))))
    (is (= :signet.impl/bad-length (error-type #(hkdf (byte-array 32) 8161))))))

;; ---- 10. sessions pass vault errors through ----

(deftest session-reports-vault-errors-as-themselves
  (let [a (vault/generate-signing-key!) b (vault/generate-signing-key!)
        i0 (session/initiator a (vault/public-key b))
        r0 (session/responder b (vault/public-key a))
        [i1 m1] (session/write-message! i0 (utf8 "1"))
        [r1 _]  (session/read-message! r0 m1)
        [_ m2]  (session/write-message! r1 (utf8 "2"))
        [i2 _]  (session/read-message! i1 m2)]
    (vault/destroy! (get-in i2 [:recv :k]))
    (is (= :signet.vault/destroyed-key (error-type #(session/read-message! i2 (byte-array 20))))
        "a destroyed key is not an authentication failure")))

;; ---- 13. smaller items ----

(deftest unbox-from-accepts-keys-and-handles
  (let [me (vault/generate-encryption-key!) peer (vault/generate-encryption-key!)
        bx (box/box peer (vault/public-key me) (utf8 "hi") {:from? false})]
    (is (:verified? (box/unbox me bx {:from peer})) "a handle")
    (is (:verified? (box/unbox me bx {:from (vault/public-key peer)})) "a public key record")
    (is (:verified? (box/unbox me bx {:from #{(:kid peer)}})) "a set of kids, as before")))

(deftest orphan-session-entries-are-not-counted
  ;; adopt-session-entry! must not record an entry the provider refused.
  (let [mem (vault/memory-provider)
        bad (reify vault/Provider
              (-generate! [_ alg] (vault/-generate! mem alg))
              (-import! [_ alg bs] (vault/-import! mem alg bs))
              (-generate-secret! [_ kid alg n] (vault/-generate-secret! mem kid alg n))
              (-adopt! [_ _ _ _] (throw (ex-info "refused" {:type ::refused})))
              (-has? [_ kid] (vault/-has? mem kid))
              (-kids [_] (vault/-kids mem))
              (-alg [_ kid] (vault/-alg mem kid))
              (-with-material [_ kid f] (vault/-with-material mem kid f))
              (-export [_ kid] (vault/-export mem kid))
              (-destroy! [_ kid] (vault/-destroy! mem kid)))]
    (vault/register-vault! :refusing bad)
    (try
      (is (= ::refused (error-type #(vault/hkdf-pair! :refusing :s (byte-array 32) (impl/random-bytes 32)))))
      (is (zero? (vault/session-entry-count :refusing)))
      (finally (vault/unregister-vault! :refusing)))))
