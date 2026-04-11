(ns signet.ssh-test
  "Tests for SSH Ed25519 key import."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.ssh :as ssh]
            [signet.key :as key]
            [signet.sign :as sign]
            [signet.chain :as chain]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; Generate a temp SSH keypair for testing
(def ^:private test-key-dir (str (System/getProperty "java.io.tmpdir") "/signet-ssh-test"))

(defn- setup-test-keys! []
  (.mkdirs (java.io.File. test-key-dir))
  (let [priv-path (str test-key-dir "/id_ed25519")
        f (java.io.File. priv-path)]
    (when-not (.exists f)
      (let [proc (-> (ProcessBuilder.
                      ["ssh-keygen" "-t" "ed25519" "-f" priv-path "-N" "" "-q"])
                     (.redirectErrorStream true)
                     (.start))]
        (.waitFor proc))))
  (str test-key-dir "/id_ed25519"))

(def ^:private test-priv-path (setup-test-keys!))

;; ---------------------------------------------------------------------------
;; Public key import
;; ---------------------------------------------------------------------------

(deftest read-public-key-test
  (let [pub-line (slurp (str test-priv-path ".pub"))
        pub-key  (ssh/read-public-key pub-line)]
    (is (some? pub-key))
    (is (key/signing-public-key? pub-key))
    (is (= 32 (count (:x pub-key))))))

;; ---------------------------------------------------------------------------
;; Private key import
;; ---------------------------------------------------------------------------

(deftest read-private-key-test
  (let [pem (slurp test-priv-path)
        kp  (ssh/read-private-key pem)]
    (is (some? kp))
    (is (key/signing-keypair? kp))
    (is (= 32 (count (:x kp))))
    (is (= 32 (count (:d kp))))))

;; ---------------------------------------------------------------------------
;; Load keypair convenience
;; ---------------------------------------------------------------------------

(deftest load-keypair-test
  (let [kp (ssh/load-keypair test-priv-path)]
    (is (some? kp))
    (is (key/signing-keypair? kp))
    ;; Should be registered in key store
    (is (some? (key/lookup (key/kid kp))))))

(deftest nonexistent-keypair-returns-nil
  (is (nil? (ssh/load-keypair "/nonexistent/path"))))

;; ---------------------------------------------------------------------------
;; SSH keys work with signet signing
;; ---------------------------------------------------------------------------

(deftest ssh-keys-sign-and-verify
  (testing "SSH keypair can sign and verify EDN envelopes"
    (let [kp       (ssh/load-keypair test-priv-path)
          envelope (sign/sign-edn kp {:action :test})
          result   (sign/verify-edn envelope)]
      (is (:valid? result))
      (is (= {:action :test} (:message result)))
      (is (= (key/kid kp) (:signer result))))))

;; ---------------------------------------------------------------------------
;; SSH keys work with signet chains
;; ---------------------------------------------------------------------------

(deftest ssh-keys-work-with-chains
  (testing "SSH keypair as chain root authority"
    (let [ssh-kp (ssh/load-keypair test-priv-path)
          token  (-> (chain/extend ssh-kp {:facts ["alice can read"]})
                     (chain/extend {:checks ["only read"]})
                     (chain/close))
          result (chain/verify token)]
      (is (:valid? result))
      (is (= (key/kid ssh-kp) (:root result)))
      (is (= 2 (count (:blocks result)))))))

;; ---------------------------------------------------------------------------
;; Public key from .pub matches derived from private key
;; ---------------------------------------------------------------------------

(deftest pub-key-consistency
  (testing "Public key from .pub file matches key derived from private key seed"
    (let [pub-from-file (ssh/read-public-key (slurp (str test-priv-path ".pub")))
          kp-from-priv  (ssh/read-private-key (slurp test-priv-path))]
      (is (java.util.Arrays/equals ^bytes (:x pub-from-file)
                                    ^bytes (:x kp-from-priv))))))
