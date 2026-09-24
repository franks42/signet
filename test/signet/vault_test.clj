(ns signet.vault-test
  "Secrets by reference (docs/07-secret-handles-design.md, decisions 7-16):
   handles, two sides indexed by one kid, keys born in the vault, explicit
   import/export, routing by vault id, and nothing secret on any output."
  (:require [cedn.core :as cedn]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.sign :as sign]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f]
                      (key/clear-key-store!)
                      (vault/reset-default-vault!)
                      (try (f)
                           (finally (doseq [id (disj (vault/vault-ids) :default)]
                                      (vault/unregister-vault! id))))))

(def ^:private ack {:i-understand :exposes-secret})

(defn- error-type [f]
  (try (f) :no-throw
       (catch clojure.lang.ExceptionInfo e (:type (ex-data e)))))

(defn- hex [^bytes bs] (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

;; ---- handles ----

(deftest handles-are-typed-values-that-name-their-vault
  (let [h (vault/generate-signing-key!)]
    (is (vault/handle? h))
    (is (= :signet/key-handle (:type h)))
    (is (= :default (:vault h)))
    (is (str/starts-with? (:kid h) "urn:signet:pk:ed25519:"))
    (is (= (:kid h) (key/kid h)) "key/kid works on handles")
    (is (= h (vault/handle (:kid h))) "the same kid gives an equal handle")
    (is (not (vault/handle? (key/signing-keypair))) "a keypair is not a handle")
    (is (not (vault/handle? {:type :signet/key-handle :kid (:kid h) :vault :default}))
        "a plain map is not a handle: the type is checked")))

(deftest handles-contain-nothing-secret
  (let [h    (vault/generate-signing-key!)
        seed (vault/export-secret h ack)]
    (doseq [[how out] [["pr-str" (pr-str h)] ["str" (str h)] ["cedn" (cedn/canonical-str h)]]]
      (is (not (str/includes? out (hex seed))) (str how " shows no secret")))
    (is (= #{:type :kid :vault} (set (keys h))))))

;; ---- keys are born in the vault ----

(deftest generated-keys-work-and-never-leave
  (let [h   (vault/generate-signing-key!)
        msg (.getBytes "hello" "UTF-8")
        sig (vault/sign h msg)]
    (is (= 64 (alength ^bytes sig)))
    (is (sign/verify (vault/public-key h) msg sig) "verifies under the public key")
    (is (= (hex sig) (hex (sign/sign h msg))) "sign/sign routes handles to their vault")
    (is (= :ed25519 (vault/algorithm h)))
    (is (= :x25519 (vault/algorithm (vault/generate-encryption-key!))))))

(deftest import-wipes-the-callers-array
  (let [kp   (key/signing-keypair)
        seed (aclone ^bytes (:d kp))
        h    (vault/import-signing-key! seed)]
    (is (every? zero? seed) "the caller's copy is wiped")
    (is (= (key/kid kp) (:kid h)) "same key, same kid")
    (is (= (hex (sign/sign kp (.getBytes "m" "UTF-8")))
           (hex (vault/sign h (.getBytes "m" "UTF-8"))))
        "signs exactly like the keypair it came from"))
  (let [x  (key/encryption-keypair)
        sk (aclone ^bytes (:d x))
        h  (vault/import-encryption-key! sk)]
    (is (every? zero? sk))
    (is (= (key/kid x) (:kid h))))
  (is (= ::vault/bad-secret (error-type #(vault/import-signing-key! (byte-array 31)))))
  (is (= ::vault/bad-secret (error-type #(vault/import-signing-key! "not bytes")))))

(deftest export-needs-the-acknowledgement
  (let [h (vault/generate-signing-key!)]
    (doseq [bad [nil {} {:i-understand true} :i-understand]]
      (is (= ::vault/export-not-acknowledged (error-type #(vault/export-secret h bad))) (pr-str bad)))
    (let [seed (vault/export-secret h ack)]
      (is (= 32 (alength ^bytes seed)))
      (is (= (:kid h) (:kid (vault/import-signing-key! :default seed)))
          "an exported seed re-imports as the same key"))))

(deftest destroy-wipes-the-secret-but-keeps-the-public-key
  (let [h (vault/generate-signing-key!)]
    (vault/destroy! h)
    (is (nil? (vault/handle (:kid h))) "the secret side no longer has it")
    (is (some? (vault/lookup (:kid h))) "the public side still knows the public key")
    (is (= ::vault/destroyed-key (error-type #(vault/sign h (byte-array 1)))))
    (is (= ::vault/destroyed-key (error-type #(vault/export-secret h ack))))
    (is (nil? (vault/destroy! h)) "destroying again is a no-op")))

;; ---- two sides, one kid ----

(deftest two-sides-indexed-by-one-kid
  (let [mine (vault/generate-signing-key!)
        peer (key/public-key (key/signing-keypair))
        kid  (vault/register-public-key! peer)]
    (testing "lookup answers from the public side, for everyone"
      (is (= (vault/public-key mine) (vault/lookup (:kid mine))))
      (is (= peer (vault/lookup kid))))
    (testing "handle answers only for keys the secret side holds"
      (is (some? (vault/handle (:kid mine))))
      (is (nil? (vault/handle kid)) "a peer's key is never mistaken for one of ours"))
    (testing "lookup falls back to parsing a 25519 kid"
      (let [stranger (key/kid (key/signing-keypair))]
        (is (some? (vault/lookup stranger)))
        (is (nil? (vault/handle stranger)))))))

;; ---- routing by vault id ----

(deftest operations-route-by-the-handles-vault
  (vault/register-vault! :team)
  (let [h (vault/generate-signing-key! :team)]
    (is (= :team (:vault h)))
    (is (some? (vault/handle :team (:kid h))))
    (is (nil? (vault/handle :default (:kid h))) "the default vault does not hold it")
    (is (= 64 (alength ^bytes (vault/sign h (byte-array 3)))))
    (testing "the same kid in two vaults: each handle names its copy"
      (let [copy (vault/import-signing-key! :default (vault/export-secret h ack))]
        (is (= (:kid h) (:kid copy)))
        (is (= :default (:vault copy)))
        (vault/destroy! h)
        (is (= 64 (alength ^bytes (vault/sign copy (byte-array 3)))) "the other copy still works")))))

(deftest unknown-vaults-never-fall-back
  (let [h (vault/->KeyHandle :signet/key-handle "urn:signet:pk:ed25519:AAAA" :nowhere)]
    (is (= ::vault/unknown-vault (error-type #(vault/sign h (byte-array 1)))))
    (is (= ::vault/unknown-vault (error-type #(vault/generate-signing-key! :nowhere)))))
  (is (= ::vault/vault-exists (error-type #(vault/register-vault! :default)))))

(deftest a-handle-is-a-reference-not-a-credential
  (let [h     (vault/generate-signing-key!)
        forged (vault/->KeyHandle :signet/key-handle (:kid h) :default)]
    (is (= forged h) "anyone can build a handle for a kid...")
    (vault/destroy! h)
    (is (= ::vault/destroyed-key (error-type #(vault/sign forged (byte-array 1))))
        "...but only the vault's contents decide what it can do")))

(deftest wrong-algorithm-and-wrong-type
  (let [x (vault/generate-encryption-key!)]
    (is (= ::vault/wrong-algorithm (error-type #(vault/sign x (byte-array 1))))))
  (is (= ::vault/not-a-handle (error-type #(vault/sign (key/signing-keypair) (byte-array 1)))))
  (is (= ::vault/not-a-handle (error-type #(vault/export-secret {:kid "x"} ack)))))

;; ---- default identity ----

(deftest default-signing-key
  (is (nil? (vault/default-signing-key)))
  (let [h (vault/ensure-default-signing-key!)]
    (is (= h (vault/default-signing-key)))
    (is (= h (vault/ensure-default-signing-key!)) "created once")
    (testing "sign-edn! signs with it"
      (is (= (:kid h) (get-in (sign/sign-edn! {:m 1}) [:envelope :signer]))))
    (testing "destroying the default clears it"
      (vault/destroy! h)
      (is (nil? (vault/default-signing-key)))))
  (testing "set-default-signing-key! refuses an encryption key"
    (is (= ::vault/wrong-algorithm
           (error-type #(vault/set-default-signing-key! (vault/generate-encryption-key!)))))))

(deftest ensure-default-under-concurrency
  (let [hs (doall (pmap (fn [_] (vault/ensure-default-signing-key!)) (range 32)))]
    (is (= 1 (count (set hs))) "every caller got the same handle")
    (is (= #{(first hs)} (vault/handles)) "the losers' keys were destroyed")
    (is (= (first hs) (vault/default-signing-key)))))

(deftest sign-edn-with-handles
  (let [h   (vault/generate-signing-key!)
        env (sign/sign-edn h {:op :read})
        r   (sign/verify-edn env {:signer (:kid h)})]
    (is (:valid? r))
    (is (:verified? r))))

;; ---- providers agree (run with the libsodium backend) ----

(deftest memory-and-sodium-providers-agree
  (if-not (= :sodium @(requiring-resolve 'signet.impl/backend))
    (is true "the :sodium provider needs the libsodium backend; covered by test:jvm-sodium / test:bb-sodium")
    (let [sodium-provider @(requiring-resolve 'signet.vault.sodium/sodium-provider)
          secret?         @(requiring-resolve 'nacljc.core/secret?)
          encrypt         @(requiring-resolve 'signet.encryption/box)
          decrypt         @(requiring-resolve 'signet.encryption/unbox)
          _    (vault/register-vault! :mem (vault/memory-provider))
          _    (vault/register-vault! :native (sodium-provider))
          kp   (key/signing-keypair)
          m    (vault/import-signing-key! :mem (aclone ^bytes (:d kp)))
          n    (vault/import-signing-key! :native (aclone ^bytes (:d kp)))
          msg  (.getBytes "same key, two enclaves" "UTF-8")]
      (is (= (:kid m) (:kid n) (key/kid kp)))
      (is (= (hex (sign/sign kp msg)) (hex (vault/sign m msg)) (hex (vault/sign n msg)))
          "byte-identical signatures")
      (is (vault/with-material n secret?) ":native lends a nacljc secret")
      (is (bytes? (vault/with-material m identity)) ":memory lends bytes")
      (testing "boxes pass between the two enclaves both ways"
        (let [xm (vault/import-encryption-key! :mem (aclone ^bytes (:d (key/encryption-keypair))))
              xn (vault/generate-encryption-key! :native)]
          (is (= "m->n" (String. ^bytes (:plaintext (decrypt xn (encrypt xm (vault/public-key xn) (.getBytes "m->n" "UTF-8")))) "UTF-8")))
          (is (= "n->m" (String. ^bytes (:plaintext (decrypt xm (encrypt xn (vault/public-key xm) (.getBytes "n->m" "UTF-8")))) "UTF-8")))))
      (testing "export and destroy behave the same"
        (is (= (hex (vault/export-secret m ack)) (hex (vault/export-secret n ack))))
        (vault/destroy! n)
        (is (= ::vault/destroyed-key (error-type #(vault/sign n msg))))))))

(deftest the-memory-provider-wipes-what-it-lends
  (vault/register-vault! :mem (vault/memory-provider))
  (let [h      (vault/generate-signing-key! :mem)
        leaked (atom nil)]
    (vault/with-material h #(reset! leaked %))
    (is (bytes? @leaked))
    (is (every? zero? @leaked) "the lent copy is zeroed as soon as the operation returns")
    (is (= 64 (alength ^bytes (vault/sign h (byte-array 1)))) "the stored key is unaffected")))
