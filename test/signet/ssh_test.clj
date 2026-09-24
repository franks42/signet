(ns signet.ssh-test
  "Tests for SSH Ed25519 key import."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
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
  (let [kp (ssh/load-keypair! test-priv-path)]
    (is (some? kp))
    (is (key/signing-keypair? kp))
    ;; load-keypair! registers it
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

;; ---------------------------------------------------------------------------
;; Anything but an unencrypted Ed25519 key is refused, never mis-parsed
;; ---------------------------------------------------------------------------

(defn- keygen!
  "A fresh key from ssh-keygen: type t, passphrase pass. Returns its path."
  [t pass]
  (let [dir  (str (java.nio.file.Files/createTempDirectory "signet-ssh-neg" (make-array java.nio.file.attribute.FileAttribute 0)))
        path (str dir "/id")]
    (.waitFor (.start (.redirectErrorStream
                       (ProcessBuilder. ^java.util.List
                        (cond-> ["ssh-keygen" "-t" t "-f" path "-N" pass "-q"]
                          (= t "rsa") (conj "-b" "2048")))
                       true)))
    path))

(defn- refusal
  "[type reason] of what f throws, or :no-throw."
  [f]
  (try (f) :no-throw
       (catch Throwable e (if-let [d (ex-data e)] [(:type d) (:reason d)] [:not-ex-info (str (class e))]))))

(defn- bad-ssh-key?
  "f is refused with ::bad-ssh-key (and, if given, this :reason)."
  ([f] (= :signet.ssh/bad-ssh-key (first (refusal f))))
  ([f reason] (= [:signet.ssh/bad-ssh-key reason] (refusal f))))

(deftest refuses-non-ed25519-public-keys
  (let [rsa (keygen! "rsa" "")]
    (is (bad-ssh-key? #(ssh/read-public-key (slurp (str rsa ".pub"))) :not-ed25519) "ssh-rsa line")
    (is (bad-ssh-key? #(ssh/read-public-key "ssh-ed25519 AAAA")) "truncated")
    (is (bad-ssh-key? #(ssh/read-public-key "not a key")))))

(deftest refuses-bad-private-keys
  (is (bad-ssh-key? #(ssh/read-private-key (slurp (keygen! "rsa" ""))) :not-ed25519) "RSA key")
  (is (bad-ssh-key? #(ssh/read-private-key (slurp (keygen! "ed25519" "secret-pass"))) :encrypted)
      "passphrase-protected: would otherwise parse ciphertext as a seed")
  (is (bad-ssh-key? #(ssh/read-private-key "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----") :not-openssh)
      "not an OpenSSH key: ex-info, not an AssertionError")
  (testing "the check-ints (OpenSSH's integrity check) must agree"
    (let [pem     (slurp test-priv-path)
          lines   (str/split-lines pem)
          b64     (apply str (remove #(str/starts-with? % "-----") lines))
          raw     (.decode (java.util.Base64/getDecoder) ^String b64)
          ;; the private blob starts after its own 4-byte length; find it by
          ;; flipping the first check-int byte: search the known layout
          flip-at (fn [^bytes bs i] (let [c (aclone bs)] (aset-byte c i (unchecked-byte (bit-xor (aget c i) 1))) c))
          ;; locate the private section: magic(15) + 3 strings + 4 + 1 string
          rd      (fn [^bytes bs pos] (let [n (reduce (fn [a i] (+ (* a 256) (bit-and (aget bs (+ pos i)) 0xff))) 0 (range 4))]
                                        (+ pos 4 n)))
          p       (-> 15 (->> (rd raw)) (->> (rd raw)) (->> (rd raw)) (+ 4) (->> (rd raw)))
          tampered (flip-at raw (+ p 4))                     ; first byte of checkint 1
          pem'    (str "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                       (.encodeToString (java.util.Base64/getEncoder) tampered)
                       "\n-----END OPENSSH PRIVATE KEY-----\n")]
      (is (some? (ssh/read-private-key pem)) "the untampered key parses")
      (is (bad-ssh-key? #(ssh/read-private-key pem') :check-int-mismatch) "a changed check-int is refused"))))

(deftest load-keypair-is-pure-and-the-twin-registers
  (is (empty? (key/registered-keys)))
  (let [kp (ssh/load-keypair test-priv-path)]
    (is (key/signing-keypair? kp))
    (is (empty? (key/registered-keys)) "load-keypair never touches the key store")
    (is (= (key/kid kp) (key/kid (ssh/load-keypair! test-priv-path))))
    (is (some? (key/lookup (key/kid kp))) "load-keypair! registered it")
    (is (= [(key/kid kp)] (map key/kid (key/registered-keys))) "exactly the key load-keypair! registered")))
