(ns signet.password-test
  "signet.password: password-derived keys as vault handles (docs/10,
   slice 1). Argon2id needs the libsodium backend; on the JCA backend the
   functions refuse with :signet.impl/unsupported (and still wipe the
   password). Tests use the minimum Argon2id cost to stay fast."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encryption :as box]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.password :as pw]
            [signet.shared :as shared]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (vault/reset-default-vault!) (f)))

(def ^:private fast {:opslimit 1 :memlimit 8192})

(def ^:private sodium? (= :sodium impl/backend))

(defn- pwd ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- utf8 ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(deftest refused-without-libsodium
  (when-not sodium?
    (let [p (pwd "correct horse")]
      (is (= :signet.impl/unsupported (error-type #(pw/password-key! p {:limits fast}))))
      (is (every? zero? p) "the password is wiped even when refused"))))

(deftest password-key-seal-and-open
  (when sodium?
    (let [p (pwd "correct horse")
          h (pw/password-key! p {:limits fast})]
      (is (vault/handle? h))
      (is (every? zero? p) "the caller's password array is wiped")
      (is (re-matches #"urn:signet:password:[A-Za-z0-9_-]+" (:kid h)))
      (let [sealed (pw/seal h (utf8 "secret note") {:aad {:file "notes"}})]
        (is (= :signet/password-sealed (:type sealed)))
        (is (every? sealed [:salt :opslimit :memlimit :nonce :commit :ct]) "the header carries the salt and cost")
        (testing "open with the handle"
          (let [r (pw/open h sealed {:aad {:file "notes"}})]
            (is (:valid? r))
            (is (= "secret note" (String. ^bytes (:plaintext r) "UTF-8")))))
        (testing "open with the password alone: derived again from the header"
          (let [p2 (pwd "correct horse")
                r  (pw/open p2 sealed)]
            (is (:valid? r))
            (is (every? zero? p2) "wiped after use")
            (is (:valid? (pw/open h sealed)) "opening with the password left the handle's key alone")))
        (testing "a wrong password"
          (is (= :wrong-password (:error (pw/open (pwd "wrong horse") sealed)))))
        (testing "tampering and a wrong aad"
          (is (= :authentication-failed
                 (:error (pw/open h (update sealed :ct (fn [^bytes c] (let [c (aclone c)] (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c)))))))
          (is (= :aad-mismatch (:error (pw/open h sealed {:aad {:file "other"}})))))
        (testing "never throws"
          (doseq [bad [nil "x" {} (assoc sealed :v 2) (dissoc sealed :salt)]]
            (is (false? (:valid? (pw/open h bad))) (pr-str (type bad)))))))))

(deftest same-password-salt-and-cost-give-the-same-key
  (when sodium?
    (let [salt (impl/random-bytes 16)
          a    (pw/password-key! (pwd "pw") {:salt (aclone salt) :limits fast})
          b    (pw/password-key! (pwd "pw") {:salt (aclone salt) :limits fast})
          c    (pw/password-key! (pwd "pw") {:limits fast})]
      (is (= (:kid a) (:kid b)) "deterministic")
      (is (not= (:kid a) (:kid c)) "a fresh salt gives another key"))))

(deftest password-keys-are-not-identities-or-shared-keys
  (when sodium?
    (let [h    (pw/password-key! (pwd "pw") {:limits fast})
          peer (vault/generate-encryption-key!)]
      (is (false? (vault/identity-key? h)))
      (is (= :signet.vault/wrong-algorithm (error-type #(vault/public-key h))))
      (is (= :signet.vault/wrong-algorithm (error-type #(box/box h (vault/public-key peer) (utf8 "x")))))
      (is (= :signet.shared/not-a-shared-key (error-type #(shared/seal h (utf8 "x"))))))))

(deftest the-root-stays-in-guarded-memory
  (when sodium?
    (let [secret? @(requiring-resolve 'nacljc.core/secret?)
          h       (pw/password-key! (pwd "pw") {:limits fast})]
      (is (vault/with-material h secret?) "under :sodium the root key is a nacljc secret")
      (is (= 0 (vault/session-entry-count)) "no temporary entry is left behind"))))

(deftest bad-options-are-refused
  (when sodium?
    (is (= :signet.password/bad-option (error-type #(pw/password-key! (pwd "pw") {:limits :fastest}))))
    (is (= :signet.password/bad-option (error-type #(pw/password-key! (pwd "pw") {:salt (byte-array 8) :limits fast}))))
    (is (= :signet.password/bad-password (error-type #(pw/password-key! "a string" {:limits fast})))
        "a String cannot be wiped: bytes only")
    (testing "the password is wiped when refused before Argon2id"
      (let [p (pwd "pw")]
        (error-type #(pw/password-key! p {:limits :fastest}))
        (is (every? zero? p) "bad option"))
      (let [p (pwd "pw")]
        (error-type #(pw/password-key! p {:salt (byte-array 8) :limits fast}))
        (is (every? zero? p) "bad salt"))
      (let [p      (pwd "pw")
            sealed (pw/seal (pw/password-key! (pwd "pw") {:limits fast}) (utf8 "x"))]
        (is (false? (:valid? (pw/open p sealed {:vault :no-such-vault}))))
        (is (every? zero? p) "open with an unknown vault")))))

(defn- secret-of
  "A nacljc secret holding s's UTF-8 bytes (as nacljc.tty would give)."
  [s]
  (@(requiring-resolve 'nacljc.core/secret-import!) (pwd s)))

(defn- destroyed? [s] (@(requiring-resolve 'nacljc.core/secret-destroyed?) s))

(deftest a-nacljc-secret-is-a-password-too
  (when sodium?
    (let [salt (impl/random-bytes 16)
          s    (secret-of "correct horse")
          h    (pw/password-key! s {:salt (aclone salt) :limits fast})]
      (is (destroyed? s) "consumed: destroyed after use")
      (is (= (:kid h) (:kid (pw/password-key! (pwd "correct horse") {:salt (aclone salt) :limits fast})))
          "the same key as the same bytes")
      (let [sealed (pw/seal h (utf8 "note"))
            s2     (secret-of "correct horse")]
        (is (:valid? (pw/open s2 sealed)) "open with a secret password")
        (is (destroyed? s2)))
      (testing "destroyed when refused, too"
        (let [s3 (secret-of "x")]
          (error-type #(pw/password-key! s3 {:limits :fastest}))
          (is (destroyed? s3)))))))
