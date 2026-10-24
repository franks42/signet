(ns signet.operations-test
  "docs/12 phase 0: providers offer operations, and signet's crypto code
   runs only those. The check: a provider that implements the Provider
   operations but does not lend material (no Lending, as a hardware token
   or an agent) carries every feature: signing, box, shared keys, Noise
   sessions, password keys and vault files (the last two need libsodium).
   If any path still lent material, it would fail here with ::not-lending
   or a missing protocol method. Secret results (DH outputs, derived and
   unwrapped keys) must stay in the provider as entries: every
   secret-producing operation returns nothing, and every temporary entry
   is destroyed by the end of each test."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encryption :as box]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.password :as pw]
            [signet.session :as session]
            [signet.shared :as shared]
            [signet.sign :as sign]
            [signet.vault :as vault]
            [signet.vault.file :as vf]))

(def ^:private sodium? (= :sodium impl/backend))

(def ^:private fast {:opslimit 1 :memlimit 8192})

(defn- utf8 ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(def ^:private secret-results
  "Calls to secret-producing operations that returned something: each one
   would be a secret leaving the provider. Must stay empty."
  (atom []))

(defn- ops-only
  "inner's Provider methods, without its Lending: a provider that runs
   operations but never lends material. Records any secret-producing
   operation that returns a value instead of filling its output entry."
  [inner]
  (let [none (fn [op r] (when (some? r) (swap! secret-results conj op)) r)]
    (reify vault/Provider
      (-generate! [_ alg] (vault/-generate! inner alg))
      (-import! [_ alg bs] (vault/-import! inner alg bs))
      (-generate-secret! [_ kid alg n] (vault/-generate-secret! inner kid alg n))
      (-adopt! [_ kid alg m] (vault/-adopt! inner kid alg m))
      (-move! [_ from to alg] (vault/-move! inner from to alg))
      (-has? [_ kid] (vault/-has? inner kid))
      (-kids [_] (vault/-kids inner))
      (-alg [_ kid] (vault/-alg inner kid))
      (-public-key [_ kid] (vault/-public-key inner kid))
      (-export [_ kid] (vault/-export inner kid))
      (-destroy! [_ kid] (vault/-destroy! inner kid))
      (-sign [_ kid m] (vault/-sign inner kid m))
      (-x25519-dh [_ kid pub out] (none :x25519-dh (vault/-x25519-dh inner kid pub out)))
      (-hkdf [_ ikm salt info outs] (none :hkdf (vault/-hkdf inner ikm salt info outs)))
      (-hmac [_ kid data] (vault/-hmac inner kid data))
      (-aead-encrypt [_ kid nonce pt aad] (vault/-aead-encrypt inner kid nonce pt aad))
      (-aead-decrypt [_ kid nonce ct aad] (vault/-aead-decrypt inner kid nonce ct aad))
      (-argon2id [_ kid salt limits out] (none :argon2id (vault/-argon2id inner kid salt limits out)))
      (-wrap [_ kid k nonce aad] (vault/-wrap inner kid k nonce aad))
      (-unwrap [_ k nonce w aad out] (none :unwrap (vault/-unwrap inner k nonce w aad out))))))

(defn- drop-vaults! []
  (doseq [id [:ops :ops2]] (when (contains? (vault/vault-ids) id) (vault/unregister-vault! id))))

(use-fixtures :each (fn [f]
                      (key/clear-key-store!)
                      (vault/reset-default-vault!)
                      (drop-vaults!)
                      (vault/register-vault! :ops (ops-only (vault/default-provider)))
                      (reset! secret-results [])
                      (try (f)
                           (is (empty? @secret-results) "no secret-producing operation returned its result")
                           (doseq [id [:ops :ops2] :when (contains? (vault/vault-ids) id)]
                             (is (zero? (vault/temp-entry-count id)) (str id ": every temporary entry was destroyed")))
                           (finally (drop-vaults!)))))

(defn- tmp-path []
  (let [d (.toFile (java.nio.file.Files/createTempDirectory "signet-ops" (make-array java.nio.file.attribute.FileAttribute 0)))]
    (.deleteOnExit d)
    (str (io/file d "vault.edn"))))

(deftest the-provider-does-not-lend
  (let [h (vault/generate-signing-key! :ops)]
    (is (= :signet.vault/not-lending (error-type #(vault/with-material h identity))))))

(deftest signing
  (let [h (vault/generate-signing-key! :ops)]
    (is (:valid? (sign/verify-edn (sign/sign-edn h {:x 1}) {:signer (:kid h)})))
    (vault/destroy! h)
    (is (= :signet.vault/destroyed-key (error-type #(sign/sign-edn h {:x 1}))))))

(deftest box-both-ways
  (let [me   (vault/generate-encryption-key! :ops)
        peer (vault/generate-encryption-key!)]
    (is (:verified? (box/unbox me (box/box peer (vault/public-key me) (utf8 "in")) {:from peer})))
    (is (:verified? (box/unbox peer (box/box me (vault/public-key peer) (utf8 "out")) {:from me})))))

(deftest shared-keys
  (let [a  (vault/generate-encryption-key! :ops)
        b  (vault/generate-encryption-key!)
        ab (shared/shared-key! a (vault/public-key b) {:context "ops/v1"})
        ba (shared/shared-key! b (vault/public-key a) {:context "ops/v1"})]
    (is (= "a->b" (String. ^bytes (:plaintext (shared/open ba (shared/seal ab (utf8 "a->b")))) "UTF-8")))
    (is (= "b->a" (String. ^bytes (:plaintext (shared/open ab (shared/seal ba (utf8 "b->a")))) "UTF-8")))
    (is (shared/verify-mac? ba (utf8 "m") (shared/mac ab (utf8 "m"))) "the peer verifies the MAC")))

(deftest noise-session
  (testing "a KK handshake and transport with the initiator's identity in the ops-only vault"
    (let [alice (vault/generate-signing-key! :ops)
          bob   (vault/generate-signing-key!)
          [a1 m1] (session/write-message! (session/initiator alice (vault/public-key bob)) (utf8 "hi"))
          [b1 p1] (session/read-message! (session/responder bob (vault/public-key alice)) m1)
          [b2 m2] (session/write-message! b1 (utf8 "hello"))
          [a2 p2] (session/read-message! a1 m2)
          [_ m3]  (session/write-message! a2 (utf8 "transport"))
          [_ p3]  (session/read-message! b2 m3)]
      (is (= ["hi" "hello" "transport"] (mapv #(String. ^bytes % "UTF-8") [p1 p2 p3])))
      (session/close! a2)
      (is (zero? (vault/session-entry-count :ops)) "close! destroys the session's entries"))))

(deftest password-keys
  (when sodium?
    (let [h (pw/password-key! (utf8 "horse") {:limits fast :vault :ops})
          s (pw/seal h (utf8 "secret"))]
      (is (= "secret" (String. ^bytes (:plaintext (pw/open h s)) "UTF-8")) "with the handle")
      (is (:valid? (pw/open (utf8 "horse") s {:vault :ops})) "with the password")
      (is (:valid? (pw/open (vault/import-password! :ops (utf8 "horse")) s {:vault :ops}))
          "with a password handle (Argon2id on its entry)"))))

(deftest vault-files
  (when sodium?
    (let [path (tmp-path)
          s    (vault/generate-signing-key! :ops)]
      (vault/set-default-signing-key! s)
      (vf/create! :ops path (utf8 "pw") {:limits fast})
      (let [rk (vf/add-recovery-key! :ops {:i-understand :exposes-secret})]
        (vf/lock! :ops)
        (vf/unlock! :ops (utf8 "pw"))
        (is (:valid? (sign/verify-edn (sign/sign-edn s {:x 1}) {:signer (:kid s)})) "unlocked with the password")
        (vault/register-vault! :ops2 (ops-only (vault/default-provider)))
        (vf/open! :ops2 path)
        (vf/unlock-with-recovery-key! :ops2 rk)
        (is (= (:kid s) (:kid (vault/default-signing-key :ops2))) "unlocked with the recovery key")
        (is (:valid? (sign/verify-edn (sign/sign-edn (vault/default-signing-key :ops2) {:x 2}) {:signer (:kid s)})))))))
