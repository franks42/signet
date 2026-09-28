(ns signet.password-handle-test
  "Password handles (docs/11, part 2, step 2): vault/import-password!
   moves a password into the vault; every function that takes a password
   takes the handle. One use by default."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.password :as pw]
            [signet.vault :as vault]
            [signet.vault.file :as vf]))

(def ^:private sodium? (= :sodium impl/backend))

(def ^:private fast {:opslimit 1 :memlimit 8192})

(defn- pwd ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- utf8 ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(defn- drop-vaults! []
  (doseq [id (vault/vault-ids) :when (not= :default id)] (vault/unregister-vault! id))
  (vault/reset-default-vault!))

(use-fixtures :each (fn [f] (key/clear-key-store!) (drop-vaults!) (try (f) (finally (drop-vaults!)))))

(defn- tmp-path []
  (let [d (.toFile (java.nio.file.Files/createTempDirectory "signet-pwh" (make-array java.nio.file.attribute.FileAttribute 0)))]
    (.deleteOnExit d)
    (str (io/file d "vault.edn"))))

(defn- vault-file!
  "Vault id with a signing key, saved to a new file with password \"pw\",
   then locked. Returns the key's handle."
  [id]
  (vault/register-vault! id)
  (let [h (vault/generate-signing-key! id)]
    (vf/create! id (tmp-path) (pwd "pw") {:limits fast})
    (vf/lock! id)
    h))

(deftest one-use-by-default
  (when sodium?
    (let [h  (vault-file! :v)
          p  (pwd "pw")
          ph (vault/import-password! p)]
      (is (every? zero? p) "the bytes are consumed")
      (is (vault/handle? ph))
      (is (re-matches #"urn:signet:password-input:.+" (:kid ph)))
      (vf/unlock! :v ph)
      (is (contains? (vault/handles :v) h) "unlocked with the handle")
      (is (nil? (vault/handle (:kid ph))) "used once: destroyed")
      (vf/lock! :v)
      (is (= :signet.vault/destroyed-key (error-type #(vf/unlock! :v ph)))))))

(deftest ask-once-unlock-several
  (when sodium?
    (let [a  (vault-file! :a)
          b  (vault-file! :b)
          ph (vault/import-password! :default (pwd "pw") {:uses 2})]
      (vf/unlock! :a ph)
      (vf/unlock! :b ph)
      (is (contains? (vault/handles :a) a))
      (is (contains? (vault/handles :b) b))
      (is (nil? (vault/handle (:kid ph))) "both uses taken"))))

(deftest keep-until-destroyed-or-locked
  (when sodium?
    (vault-file! :v)
    (let [ph (vault/import-password! :default (pwd "pw") {:keep true})]
      (dotimes [_ 3] (vf/unlock! :v ph) (vf/lock! :v))
      (is (some? (vault/handle (:kid ph))) "still there")
      (vault/destroy! ph)
      (is (= :signet.vault/destroyed-key (error-type #(vf/unlock! :v ph))))))
  (when sodium?
    (testing "lock! of its own vault destroys it"
      (vault/register-vault! :w)
      (vf/create! :w (tmp-path) (pwd "x") {:limits fast})
      (let [ph (vault/import-password! :w (pwd "pw") {:keep true})]
        (vf/lock! :w)
        (is (= :signet.vault/vault-locked (error-type #(vault/with-material ph identity))))))))

(deftest a-handle-works-for-password-keys-too
  (when sodium?
    (let [salt (impl/random-bytes 16)
          a    (pw/password-key! (vault/import-password! (pwd "horse")) {:salt (aclone salt) :limits fast})
          b    (pw/password-key! (pwd "horse") {:salt (aclone salt) :limits fast})
          sealed (pw/seal a (utf8 "note"))]
      (is (= (:kid a) (:kid b)))
      (is (:valid? (pw/open (vault/import-password! (pwd "horse")) sealed))))))

(deftest the-last-use-goes-to-one-caller
  (when sodium?
    (vault/register-vault! :c1)
    (let [ph      (vault/import-password! :default (pwd "pw"))
          go      (promise)
          results (doall (for [_ (range 4)]
                           (future @go (error-type #(pw/password-key! ph {:limits fast :vault :c1})))))]
      (deliver go true)
      (let [rs (map deref results)]
        (is (= 1 (count (filter #{:no-throw} rs))) (pr-str rs))
        (is (every? #{:no-throw :signet.vault/destroyed-key} rs))))))

(deftest refused-inputs-are-consumed
  (when sodium?
    (let [p (pwd "pw")]
      (is (= :signet.vault/bad-option (error-type #(vault/import-password! :default p {:uses 0}))))
      (is (every? zero? p)))
    (is (= :signet.vault/bad-password (error-type #(vault/import-password! "a string"))))
    (testing "a password-key handle is not a password"
      (vault-file! :v)
      (let [k (pw/password-key! (pwd "pw") {:limits fast})]
        (is (= :signet.vault.file/bad-password (error-type #(vf/unlock! :v k))))))))
