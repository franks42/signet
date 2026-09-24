(ns signet.trust-test
  "Key-store hygiene, ephemeral-key discipline and verification semantics.

   Vocabulary used by signet:
     valid     — well-formed, the signature checks out under the key named
                 in :signer, and not expired. Self-consistency only: any
                 stranger can produce a valid envelope.
     verified  — valid AND the signer (or a chain's root) is the identity
                 the caller expected (:signer / :root option).
     authorized — whether that identity may do this: policy, not signet's
                 job (a policy decision point such as stroopwafel's).

   Ephemeral keys are used once and discarded: never registered in any key
   store, dropped from protocol state, and their secret bytes zeroed —
   otherwise there is no forward secrecy."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.chain :as chain]
            [signet.key :as key]
            [signet.session :as session]
            [signet.sign :as sign]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

(defn- store-kids [] (set (map key/kid (key/registered-keys))))

(defn- stranger-envelope
  "A validly signed envelope from a key the verifier has never seen."
  [payload]
  (let [kp (key/signing-keypair)
        env (sign/sign-edn kp payload)]
    (key/clear-key-store!)
    env))

(defn- all-zero? [^bytes bs] (every? zero? (seq bs)))

;; ---------------------------------------------------------------------------
;; Key store: only what the caller deliberately registers
;; ---------------------------------------------------------------------------

(deftest lookup-does-not-register
  (testing "lookup parses a self-describing kid without adding it to the store"
    (let [kp  (key/signing-keypair)
          kid (key/kid kp)]
      (key/clear-key-store!)
      (is (= (seq (:x kp)) (seq (:x (key/lookup kid)))) "still returns the public key")
      (is (empty? (key/registered-keys)) "but the store stays empty"))))

(deftest verifying-strangers-does-not-grow-the-store
  (let [envs (doall (repeatedly 50 #(stranger-envelope {:n 1})))]
    (doseq [e envs] (sign/verify-edn e))
    (is (empty? (key/registered-keys))
        "untrusted input must not be able to grow the verifier's memory")))

;; ---------------------------------------------------------------------------
;; Ephemeral keys: never registered, dropped after use, zeroed
;; ---------------------------------------------------------------------------

(defn- handshake
  "Complete a Noise_KK handshake between identities a and b; returns the
   intermediate and final states."
  [a b]
  (let [i0 (session/initiator a (key/public-key b))
        r0 (session/responder b (key/public-key a))
        [i1 m1] (session/write-message! i0 (.getBytes "hi" "UTF-8"))
        [r1 _]  (session/read-message! r0 m1)
        [r2 m2] (session/write-message! r1 (.getBytes "yo" "UTF-8"))
        [i2 _]  (session/read-message! i1 m2)]
    {:i1 i1 :r1 r1 :i2 i2 :r2 r2}))

(deftest session-ephemerals-never-registered
  (let [a      (key/encryption-keypair!)
        b      (key/encryption-keypair!)
        before (store-kids)
        {:keys [i2 r2]} (handshake a b)]
    (is (session/established? i2))
    (is (session/established? r2))
    (is (= 2 (count before)) "only the two static identity keypairs")
    (is (= before (store-kids)) "the handshake registered nothing")))

(deftest session-ephemerals-dropped-and-zeroed
  (let [{:keys [i1 r1 i2 r2]} (handshake (key/encryption-keypair) (key/encryption-keypair))
        i-eph (:local-ephemeral-kp i1)]
    (testing "the initiator's ephemeral exists only between messages 1 and 2"
      (is (some? (:d i-eph)) "i1 is waiting for message 2, so it must hold it"))
    (testing "the responder's ephemeral never appears in any returned state:
              it is created, used and wiped inside the call that writes message 2"
      (is (nil? (:local-ephemeral-kp r1)))
      (is (nil? (:local-ephemeral-kp r2))))
    (testing "the established states hold no ephemeral material"
      (doseq [st [i2 r2]]
        (is (nil? (:local-ephemeral-kp st)))
        (is (nil? (:remote-ephemeral-pub st)))))
    (testing "the initiator's ephemeral private key bytes were zeroed once used"
      (is (all-zero? (:d i-eph))))))

(deftest chain-ephemerals-never-registered
  (let [root   (key/signing-keypair)
        before (store-kids)
        token  (-> (chain/extend root {:facts [1]})
                   (chain/extend {:checks [2]}))]
    (is (= before (store-kids)) "extending registered no ephemeral keys")
    (is (:valid? (chain/verify token)) "verification works without registration")
    (is (:valid? (chain/verify (chain/close token))))
    (is (= before (store-kids)) "nor did verifying or sealing")))

;; ---------------------------------------------------------------------------
;; verify-edn: never throws, expiry counts, optional expected signer
;; ---------------------------------------------------------------------------

(deftest expired-is-not-valid
  (let [kp  (key/signing-keypair)
        env (sign/sign-edn kp {:msg "old"} {:ttl 0})]
    (Thread/sleep 5)
    (let [r (sign/verify-edn env)]
      (is (true? (:signature-valid? r)) "the signature itself is fine")
      (is (true? (:expired? r)))
      (is (false? (:valid? r)) "but an expired envelope is not valid"))))

(deftest verify-edn-never-throws-on-malformed-input
  (let [good (sign/sign-edn (key/signing-keypair) {:a 1})]
    (doseq [[label env] [["nil" nil]
                         ["not a map" "garbage"]
                         ["no envelope" {:type :signet/signed}]
                         ["no signature" (dissoc good :signature)]
                         ["short signature" (assoc good :signature (byte-array 10))]
                         ["signature not bytes" (assoc good :signature "sig")]
                         ["nil request-id" (assoc-in good [:envelope :request-id] nil)]
                         ["v4 request-id" (assoc-in good [:envelope :request-id] (random-uuid))]
                         ["garbage signer" (assoc-in good [:envelope :signer] "urn:signet:pk:ed25519:!!!")]
                         ["non-urn signer" (assoc-in good [:envelope :signer] "alice")]
                         ["unencodable message" (assoc-in good [:envelope :message] (Object.))]]]
      (let [r (try (sign/verify-edn env) (catch Throwable t {:threw (str (class t) " " (ex-message t))}))]
        (is (not (contains? r :threw)) (str label ": " (:threw r)))
        (is (false? (:valid? r)) label)))))

(deftest expected-signer
  (let [alice (key/signing-keypair)
        mallory (key/signing-keypair)
        env   (sign/sign-edn mallory {:transfer 1000000})]
    (testing "without an expectation, any valid signer is valid (not verified)"
      (is (true? (:valid? (sign/verify-edn env))))
      (is (nil? (:verified? (sign/verify-edn env)))))
    (testing "with an expected signer, a different signer is rejected"
      (let [r (sign/verify-edn env {:signer (key/kid alice)})]
        (is (false? (:valid? r)))
        (is (false? (:verified? r)))))
    (testing "the expected signer verifies"
      (let [r (sign/verify-edn (sign/sign-edn alice {:ok 1}) {:signer (key/kid alice)})]
        (is (true? (:valid? r)))
        (is (true? (:verified? r)))))
    (testing ":signer may be a set of acceptable kids"
      (is (true? (:verified? (sign/verify-edn env {:signer #{(key/kid alice) (key/kid mallory)}})))))))

(deftest chain-expected-root
  (let [root (key/signing-keypair)
        evil (key/signing-keypair)
        good-token (chain/extend root {:facts [[:right :read]]})
        evil-token (chain/extend evil {:facts [[:right :admin]]})]
    (testing "a self-minted chain is valid (self-consistent) but not verified"
      (is (true? (:valid? (chain/verify evil-token)))))
    (testing "with the expected root, the self-minted chain is rejected"
      (let [r (chain/verify evil-token {:root (key/kid root)})]
        (is (false? (:valid? r)))
        (is (false? (:verified? r)))))
    (testing "the genuine chain verifies against its root"
      (is (true? (:verified? (chain/verify good-token {:root (key/kid root)})))))))

;; ---------------------------------------------------------------------------
;; dh vs edh: misuse fails loudly instead of relying on the reader
;; ---------------------------------------------------------------------------

(def ^:private fresh-ephemeral @#'session/fresh-ephemeral)
(def ^:private dh  @#'session/dh)
(def ^:private edh @#'session/edh)

(defn- throws-type [f]
  (try (f) :no-throw
       (catch clojure.lang.ExceptionInfo e (:type (ex-data e)))))

(deftest ephemerals-have-their-own-type
  (let [eph (fresh-ephemeral)]
    (is (= :signet/ephemeral-x25519-keypair (:type eph)))
    (is (= 32 (count (:d eph))))))

(deftest dh-vs-edh-misuse-throws
  (let [static-a (key/encryption-keypair)
        static-b (key/public-key (key/encryption-keypair))
        eph      (fresh-ephemeral)]
    (testing "correct use works"
      (is (= 32 (count (dh static-a static-b))) "ss: static x static")
      (is (= 32 (count (edh eph static-b))) "es/se: ephemeral x static")
      (is (= 32 (count (edh static-a eph))) "static x ephemeral public"))
    (testing "dh refuses any ephemeral input"
      (is (= :signet.session/ephemeral-in-dh (throws-type #(dh eph static-b))))
      (is (= :signet.session/ephemeral-in-dh (throws-type #(dh static-a eph)))))
    (testing "edh refuses two static keys"
      (is (= :signet.session/no-ephemeral-in-edh (throws-type #(edh static-a static-b)))))))

(deftest ephemerals-cannot-be-registered
  (is (= :signet.key/ephemeral-key (throws-type #(key/register! (fresh-ephemeral))))
      "register! refuses ephemeral keys loudly instead of ignoring them"))

;; ---------------------------------------------------------------------------
;; Session states are single-use: a reused state can never reuse a nonce
;; ---------------------------------------------------------------------------

(defn- stale? [f]
  (= :signet.session/stale-session-state (throws-type f)))

(defn- transport-pair
  "Established [initiator responder] transport states."
  []
  (let [{:keys [i2 r2]} (handshake (key/encryption-keypair) (key/encryption-keypair))]
    [i2 r2]))

(deftest second-write-from-same-state-is-refused
  (let [[alice _bob] (transport-pair)
        [alice' _c1] (session/write-message! alice (.getBytes "first" "UTF-8"))]
    (is (stale? #(session/write-message! alice (.getBytes "second" "UTF-8")))
        "writing again from the consumed state would reuse its nonce")
    (is (vector? (session/write-message! alice' (.getBytes "second" "UTF-8")))
        "the returned state is the one to use")))

(deftest second-write-from-handshake-state-is-refused
  (let [a  (key/encryption-keypair)
        b  (key/encryption-keypair)
        i0 (session/initiator a (key/public-key b))]
    (session/write-message! i0 (.getBytes "m1" "UTF-8"))
    (is (stale? #(session/write-message! i0 (.getBytes "m1'" "UTF-8"))))))

(deftest replay-into-stale-receiver-state-is-refused
  (let [[alice bob] (transport-pair)
        [_ ct] (session/write-message! alice (.getBytes "pay 10" "UTF-8"))]
    (session/read-message! bob ct)
    (is (stale? #(session/read-message! bob ct))
        "the same ciphertext cannot be accepted twice from a stale state")))

(deftest failed-read-does-not-consume-the-state
  (let [[alice bob] (transport-pair)
        [_ ct] (session/write-message! alice (.getBytes "genuine" "UTF-8"))
        forged (let [c (aclone ^bytes ct)] (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c)]
    (is (thrown? Exception (session/read-message! bob forged)) "forgery rejected")
    (let [[_ pt] (session/read-message! bob ct)]
      (is (= "genuine" (String. ^bytes pt "UTF-8"))
          "the genuine message still decrypts: a failed read left the state usable"))))

(deftest concurrent-writes-from-one-state-yield-one-ciphertext
  (let [[alice _] (transport-pair)
        results (->> (range 16)
                     (mapv (fn [i] (future
                                     (try (second (session/write-message! alice (.getBytes (str i) "UTF-8")))
                                          (catch clojure.lang.ExceptionInfo e (:type (ex-data e)))))))
                     (mapv deref))
        cts (filter bytes? results)]
    (is (= 1 (count cts)) "exactly one writer wins; no second ciphertext under the same nonce")
    (is (every? #{:signet.session/stale-session-state} (remove bytes? results)))))
