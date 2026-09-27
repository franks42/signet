(ns signet.vault-file-test
  "signet.vault.file: vault files, password unlocking, the optional
   recovery key (docs/10, slice 2). Argon2id needs the libsodium backend;
   on JCA only the refusal is tested. Tests use the minimum Argon2id cost."
  (:require [cedn.core :as cedn]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encoding :as enc]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.password :as pw]
            [signet.shared :as shared]
            [signet.sign :as sign]
            [signet.vault :as vault]
            [signet.vault.file :as vf]))

(def ^:private sodium? (= :sodium impl/backend))

(def ^:private fast {:opslimit 1 :memlimit 8192})

(defn- pwd ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(defn- drop-vaults! []
  (doseq [id (vault/vault-ids) :when (not= :default id)] (vault/unregister-vault! id))
  (vault/reset-default-vault!))

(use-fixtures :each (fn [f] (key/clear-key-store!) (drop-vaults!) (try (f) (finally (drop-vaults!)))))

(defn- tmp-path []
  (let [d (.toFile (java.nio.file.Files/createTempDirectory "signet-vault" (make-array java.nio.file.attribute.FileAttribute 0)))]
    (.deleteOnExit d)
    (str (io/file d "vault.edn"))))

(defn- read-edn [path] (edn/read-string {:readers cedn/readers} (slurp path)))

(defn- write-edn! [path v] (spit path (cedn/canonical-str v)))

(defn- flip-first-byte ^bytes [^bytes bs]
  (let [c (aclone bs)] (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c))

(defn- setup!
  "A vault :v with a signing key (the default), an encryption key and a
   peer's public key, saved to a new file. Returns the handles and path."
  [& [opts]]
  (let [path (tmp-path)]
    (vault/register-vault! :v)
    (let [s    (vault/generate-signing-key! :v)
          e    (vault/generate-encryption-key! :v)
          peer (vault/public-key (vault/generate-signing-key!))]
      (vault/register-public-key! :v peer)
      (vault/set-default-signing-key! s)
      (vf/create! :v path (pwd "correct horse") (merge {:limits fast} opts))
      {:path path :s s :e e :peer (key/kid peer)})))

(deftest refused-without-libsodium
  (when-not sodium?
    (let [p    (pwd "pw")
          path (tmp-path)]
      (is (= :signet.impl/unsupported (error-type #(vf/create! :v path p {:limits fast}))))
      (is (every? zero? p) "the password is wiped even when refused")
      (is (not (contains? (vault/vault-ids) :v)) "the vault it registered is gone again")
      (is (not (.exists (io/file path)))))))

(deftest save-lock-and-unlock
  (when sodium?
    (let [{:keys [path s e peer]} (setup!)
          signed (sign/sign-edn s {:hello 1})]
      (is (= {:path path :locked? false :dirty? false :auto-save? false
              :unlocked-by :password :recovery-key? false}
             (vf/status :v)))
      (testing "locked: no secrets, no public side, no writes"
        (vf/lock! :v)
        (is (:locked? (vf/status :v)))
        (is (empty? (vault/handles :v)))
        (is (= :signet.vault/vault-locked (error-type #(sign/sign-edn s {:x 1}))))
        (is (= :signet.vault/vault-locked (error-type #(vault/generate-signing-key! :v))))
        (is (= :signet.vault/vault-locked (error-type #(vault/register-public-key! :v (vault/lookup peer)))))
        (is (nil? (vault/default-signing-key :v))))
      (testing "a wrong password loads nothing"
        (let [p (pwd "wrong horse")]
          (is (= :signet.vault.file/bad-password (error-type #(vf/unlock! :v p))))
          (is (every? zero? p) "wiped"))
        (is (:locked? (vf/status :v)))
        (is (empty? (vault/handles :v))))
      (testing "the right password brings everything back"
        (let [p (pwd "correct horse")]
          (vf/unlock! :v p)
          (is (every? zero? p) "wiped"))
        (is (= #{s e} (vault/handles :v)))
        (is (= s (vault/default-signing-key :v)))
        (is (:valid? (sign/verify-edn (sign/sign-edn s {:x 1}) {:signer (:kid s)})))
        (is (:valid? (sign/verify-edn signed {:signer (:kid s)})))
        (is (= (vault/public-key s) (vault/lookup :v (:kid s))))
        (is (= peer (key/kid (vault/lookup :v peer))))
        (is (= :signet.vault.file/already-unlocked (error-type #(vf/unlock! :v (pwd "correct horse")))))))))

(deftest open-in-a-new-process
  (when sodium?
    (let [{:keys [path s e]} (setup!)
          seed (vault/export-secret s {:i-understand :exposes-secret})]
      (vf/lock! :v)
      (vault/unregister-vault! :v)
      (vault/reset-default-vault!)            ; as in a fresh process
      (testing "open! into the :default vault (empty at start), then unlock!"
        (vf/open! :default path)
        (is (:locked? (vf/status :default)))
        (vf/unlock! :default (pwd "correct horse"))
        (is (= #{(:kid s) (:kid e)} (set (map :kid (vault/handles :default)))))
        (is (= (seq seed) (seq (vault/export-secret (vault/handle :default (:kid s)) {:i-understand :exposes-secret})))
            "the same seed")
        (is (= (:kid s) (:kid (vault/default-signing-key :default))))))))

(deftest the-file-holds-no-secret
  (when sodium?
    (let [{:keys [path s e]} (setup!)
          text (slurp path)
          raw  (.getBytes ^String text "ISO-8859-1")]
      (doseq [h [s e]
              :let [sk (vault/export-secret h {:i-understand :exposes-secret})]]
        (is (not (str/includes? text (enc/bytes->hex sk))) "not as hex")
        (is (not (str/includes? text (enc/bytes->base64url sk))) "not as base64url")
        (is (not (some #(java.util.Arrays/equals ^bytes sk ^bytes %)
                       (map #(java.util.Arrays/copyOfRange raw (int %) (int (+ % 32))) (range (- (alength raw) 31)))))
            "not as raw bytes"))
      (is (not (str/includes? text (:kid s))) "which keys it holds is encrypted too")
      (is (= #{:type :v :unlock :salt :body} (set (keys (read-edn path)))))
      (is (= "rw-------" (java.nio.file.attribute.PosixFilePermissions/toString
                          (java.nio.file.Files/getPosixFilePermissions (.toPath (io/file path))
                                                                       (make-array java.nio.file.LinkOption 0))))))))

(deftest guards
  (when sodium?
    (let [{:keys [path]} (setup!)]
      (testing "create! never overwrites, and one file per vault"
        (vault/register-vault! :w)
        (is (= :signet.vault.file/file-exists (error-type #(vf/create! :w path (pwd "x") {:limits fast}))))
        (is (= :signet.vault.file/has-file (error-type #(vf/create! :v (str path ".2") (pwd "x") {:limits fast})))))
      (testing "open! only into a new or empty vault"
        (vault/generate-signing-key! :w)
        (is (= :signet.vault.file/vault-not-empty (error-type #(vf/open! :w path)))))
      (testing "a vault without a file"
        (is (= :signet.vault.file/no-file (error-type #(vf/save! :w))))
        (is (nil? (vf/status :w))))
      (testing "lock! refuses to lose changes"
        (vault/generate-signing-key! :v)
        (is (:dirty? (vf/status :v)))
        (is (= :signet.vault.file/unsaved-changes (error-type #(vf/lock! :v))))
        (vf/lock! :v {:discard-changes? true})
        (vf/unlock! :v (pwd "correct horse"))
        (is (= 2 (count (vault/handles :v))) "the unsaved key is gone"))
      (testing "passwords are bytes"
        (is (= :signet.vault.file/bad-password (error-type #(vf/change-password! :v "correct horse" (pwd "n")))))
        (is (= :signet.vault.file/bad-file (error-type #(vf/open! :x (str path ".missing")))))))))

(deftest save-and-auto-save
  (when sodium?
    (testing "explicit save!"
      (let [{:keys [path]} (setup!)
            h (vault/generate-encryption-key! :v)]
        (vf/save! :v)
        (is (false? (:dirty? (vf/status :v))))
        (vf/lock! :v)
        (vf/unlock! :v (pwd "correct horse"))
        (is (contains? (vault/handles :v) h))
        (testing "destroying a key is a change too"
          (vault/destroy! h)
          (is (:dirty? (vf/status :v)))
          (vf/save! :v)
          (vf/lock! :v)
          (vf/unlock! :v (pwd "correct horse"))
          (is (not (contains? (vault/handles :v) h))))
        (vf/lock! :v)
        (vault/unregister-vault! :v)
        (testing ":auto-save on open!"
          (vf/open! :v path {:auto-save true})
          (vf/unlock! :v (pwd "correct horse"))
          (let [h2 (vault/generate-signing-key! :v)]
            (is (false? (:dirty? (vf/status :v))) "saved at once")
            (vf/lock! :v)
            (vf/unlock! :v (pwd "correct horse"))
            (is (contains? (vault/handles :v) h2))))))))

(deftest change-password
  (when sodium?
    (let [{:keys [s]} (setup!)
          old (pwd "wrong")]
      (is (= :signet.vault.file/bad-password (error-type #(vf/change-password! :v old (pwd "new") {:limits fast}))))
      (is (every? zero? old))
      (let [o (pwd "correct horse") n (pwd "battery staple")]
        (vf/change-password! :v o n {:limits fast})
        (is (and (every? zero? o) (every? zero? n))))
      (vf/lock! :v)
      (is (= :signet.vault.file/bad-password (error-type #(vf/unlock! :v (pwd "correct horse")))))
      (vf/unlock! :v (pwd "battery staple"))
      (is (contains? (vault/handles :v) s))
      (is (= :signet.vault.file/recovery-unlock-required
             (error-type #(vf/reset-password! :v (pwd "x") {:limits fast})))
          "reset-password! needs a recovery unlock"))))

(deftest recovery-key
  (when sodium?
    (let [{:keys [path s]} (setup!)]
      (is (= :signet.vault.file/not-acknowledged (error-type #(vf/add-recovery-key! :v {}))))
      (let [rk  (vf/add-recovery-key! :v {:i-understand :exposes-secret})
            txt (String. ^bytes rk "US-ASCII")]
        (is (re-matches #"SIGNET-RK1(-[0-9A-HJKMNP-TV-Z]{4}){14}" txt))
        (is (:recovery-key? (vf/status :v)))
        (vf/lock! :v)
        (testing "a typo is caught by the checksum"
          (let [typo (str (subs txt 0 12) (if (= \A (.charAt txt 12)) "B" "A") (subs txt 13))]
            (is (= :signet.vault.file/bad-recovery-key (error-type #(vf/unlock-with-recovery-key! :v (pwd typo)))))
            (is (= :signet.vault.file/bad-recovery-key (error-type #(vf/unlock-with-recovery-key! :v (pwd "SIGNET-RK1-ABCD")))))
            (is (= :signet.vault.file/bad-recovery-key (error-type #(vf/unlock-with-recovery-key! :v (pwd (subs txt 11))))))))
        (testing "another vault's key"
          (vault/register-vault! :other)
          (vf/create! :other (str path ".other") (pwd "pw") {:limits fast})
          (let [other (vf/add-recovery-key! :other {:i-understand :exposes-secret})]
            (is (= :signet.vault.file/wrong-recovery-key (error-type #(vf/unlock-with-recovery-key! :v other))))
            (is (every? zero? other) "wiped")))
        (testing "lower case, without dashes, O for 0 and so on: it still opens"
          (let [sloppy (-> txt (subs 11) (str/replace "-" "") str/lower-case (str/replace "0" "o") (str/replace "1" "l"))
                in     (pwd (str "signet-rk1-" sloppy))]
            (vf/unlock-with-recovery-key! :v in)
            (is (every? zero? in) "wiped")
            (is (= :recovery-key (:unlocked-by (vf/status :v))))
            (is (contains? (vault/handles :v) s))))
        (testing "reset-password! after a recovery unlock"
          (vf/reset-password! :v (pwd "new horse") {:limits fast})
          (vf/lock! :v)
          (is (= :signet.vault.file/bad-password (error-type #(vf/unlock! :v (pwd "correct horse")))))
          (vf/unlock! :v (pwd "new horse")))
        (testing "remove-recovery-key! revokes it"
          (vf/remove-recovery-key! :v)
          (vf/lock! :v)
          (is (= :signet.vault.file/no-recovery-key (error-type #(vf/unlock-with-recovery-key! :v (pwd txt))))))
        (testing "add-recovery-key! later replaces the old key"
          (vf/unlock! :v (pwd "new horse"))
          (vf/add-recovery-key! :v {:i-understand :exposes-secret})
          (vf/remove-recovery-key! :v)
          (vf/add-recovery-key! :v {:i-understand :exposes-secret})
          (vf/lock! :v)
          (is (= :signet.vault.file/wrong-recovery-key (error-type #(vf/unlock-with-recovery-key! :v (pwd txt))))))))))

(deftest tampering
  (when sodium?
    (let [{:keys [path]} (setup!)
          reopen (fn [f]
                   (vault/unregister-vault! :v)
                   (write-edn! path f)
                   (vf/open! :v path))
          orig (read-edn path)]
      (vf/lock! :v)
      (testing "a changed body"
        (reopen (update orig :body flip-first-byte))
        (is (= :signet.vault.file/corrupt-file (error-type #(vf/unlock! :v (pwd "correct horse")))))
        (is (:locked? (vf/status :v)) "stays locked")
        (is (empty? (vault/handles :v)) "nothing loaded"))
      (testing "a changed salt: the header is the body's associated data"
        (reopen (update orig :salt flip-first-byte))
        (is (= :signet.vault.file/corrupt-file (error-type #(vf/unlock! :v (pwd "correct horse"))))))
      (testing "a lowered cost in the unlock entry"
        (reopen (assoc-in orig [:unlock 0 :memlimit] 16384))
        (is (= :signet.vault.file/bad-password (error-type #(vf/unlock! :v (pwd "correct horse"))))))
      (testing "not a vault file"
        (vault/unregister-vault! :v)
        (write-edn! path (assoc orig :v 2))
        (is (= :signet.vault.file/bad-file (error-type #(vf/open! :v path)))))
      (testing "the original still opens"
        (write-edn! path orig)
        (vf/open! :v path)
        (vf/unlock! :v (pwd "correct horse"))
        (is (= 2 (count (vault/handles :v))))))))

(deftest secrets-stay-in-guarded-memory
  (when sodium?
    (let [secret? @(requiring-resolve 'nacljc.core/secret?)
          {:keys [s e]} (setup!)]
      (vf/lock! :v)
      (vf/unlock! :v (pwd "correct horse"))
      (is (vault/with-material s secret?) "a loaded key is a nacljc secret")
      (is (vault/with-material e secret?))
      (is (= 0 (vault/session-entry-count :v))))))

(deftest the-memory-provider-works-too
  ;; keys as heap bytes: the unlock key, master key and keys follow the provider
  (when sodium?
    (let [path (tmp-path)]
      (vault/register-vault! :m (vault/memory-provider))
      (let [s (vault/generate-signing-key! :m)]
        (vf/create! :m path (pwd "pw") {:limits fast})
        (vf/add-recovery-key! :m {:i-understand :exposes-secret})
        (vf/lock! :m)
        (vf/unlock! :m (pwd "pw"))
        (is (bytes? (vault/with-material s aclone)))
        (is (:valid? (sign/verify-edn (sign/sign-edn s {:x 1}) {:signer (:kid s)})))))))

(deftest lock-destroys-every-secret
  (when sodium?
    (let [{:keys [s e]} (setup!)
          peer (vault/generate-encryption-key!)
          sk   (shared/shared-key! e (vault/public-key peer))
          pk   (pw/password-key! (pwd "other") {:limits fast :vault :v})]
      (vf/lock! :v)
      (doseq [h [s e sk pk]]
        (is (= :signet.vault/vault-locked (error-type #(vault/with-material h identity))) (pr-str (:kid h))))
      (vf/unlock! :v (pwd "correct horse"))
      (is (= #{s e} (vault/handles :v)) "shared and password keys are not saved: derive them again")
      (is (= :signet.vault/destroyed-key (error-type #(vault/with-material sk identity)))))))

(deftest the-header-binds-the-unlock-list
  (when sodium?
    (let [{:keys [path]} (setup!)]
      (vf/add-recovery-key! :v {:i-understand :exposes-secret})
      (vf/lock! :v)
      (let [f (read-edn path)]
        (vault/unregister-vault! :v)
        (write-edn! path (update f :unlock #(vec (remove (comp #{:recovery-key} :method) %))))
        (vf/open! :v path)
        (is (= :signet.vault.file/corrupt-file (error-type #(vf/unlock! :v (pwd "correct horse"))))
            "removing an unlock entry is noticed")))))

(deftest passwords-are-wiped-when-refused
  (when sodium?
    (let [{:keys [path]} (setup!)]
      (let [p (pwd "x")]
        (error-type #(vf/create! :w path p {:limits fast}))
        (is (every? zero? p) "create! onto an existing file"))
      (let [p (pwd "x")]
        (error-type #(vf/unlock! :v p))
        (is (every? zero? p) "unlock! of an unlocked vault"))
      (let [o (pwd "correct horse") n (pwd "n")]
        (error-type #(vf/change-password! :v o n {:limits :fastest}))
        (is (and (every? zero? o) (every? zero? n)) "bad limits")))))
