(ns signet.secp256k1-test
  "secp256k1 ECDSA tests — JVM-only.

   These exercise the BouncyCastle-backed paths in
   signet.impl.jvm-secp256k1. They will not run on babashka because
   BC isn't in bb's SCI class allowlist (covered separately in
   signet.bb-smoke-test).

   Includes both:
     - roundtrip tests (keygen → sign → verify own output)
     - external fixture (openssl-generated) verify, exercising
       interop with non-signet ECDSA producers"
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encoding :as enc]
            [signet.impl.jvm-secp256k1 :as bc-secp]
            [signet.key :as key]
            [signet.sign :as sign]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; -- Roundtrip tests --

(deftest secp256k1-keygen
  (testing "keypair generation via BouncyCastle"
    (let [kp (key/signing-keypair :secp256k1)]
      (is (= :signet/secp256k1-keypair (:type kp)))
      (is (= :secp256k1 (:crv kp)))
      (is (= 33 (count (:x kp))) "compressed sec1 pub is 33 bytes")
      (is (= 32 (count (:d kp))) "scalar is 32 bytes")
      (is (#{0x02 0x03} (bit-and (aget ^bytes (:x kp) 0) 0xff))
          "compressed-pub leading byte is 0x02 or 0x03"))))

(deftest secp256k1-sign-verify-roundtrip
  (testing "sign + verify roundtrip with raw 64-byte signature output"
    (let [kp  (key/signing-keypair :secp256k1)
          msg (.getBytes "hello secp256k1 ECDSA" "UTF-8")
          sig (sign/sign kp msg)]
      (is (= 64 (count sig)) "raw r||s = 64 bytes")
      (is (sign/verify kp msg sig)))))

(deftest secp256k1-rejects-tampered-msg
  (testing "verify returns false on tampered message"
    (let [kp  (key/signing-keypair :secp256k1)
          msg (.getBytes "original" "UTF-8")
          sig (sign/sign kp msg)]
      (is (not (sign/verify kp (.getBytes "tampered" "UTF-8") sig))))))

(deftest secp256k1-rejects-wrong-key
  (testing "verify returns false with a different keypair's pubkey"
    (let [kp1 (key/signing-keypair :secp256k1)
          kp2 (key/signing-keypair :secp256k1)
          msg (.getBytes "msg" "UTF-8")
          sig (sign/sign kp1 msg)]
      (is (not (sign/verify kp2 msg sig))))))

(deftest secp256k1-verify-malformed-sig-no-throw
  (testing "verify returns false on garbage signature input — never throws"
    (let [kp  (key/signing-keypair :secp256k1)
          msg (.getBytes "x" "UTF-8")]
      (is (false? (sign/verify kp msg (byte-array [1 2 3 4]))))
      (is (false? (sign/verify kp msg (byte-array 64))))   ; all-zero raw
      (is (false? (sign/verify kp msg (byte-array 70))))))) ; all-zero DER-shaped

;; -- DER ↔ raw auto-detection --

(deftest secp256k1-verify-accepts-raw-and-der
  (testing "verify auto-detects raw r||s and DER, accepts both equivalently"
    (let [kp  (key/signing-keypair :secp256k1)
          msg (.getBytes "hello DER-or-raw" "UTF-8")
          raw (sign/sign kp msg)
          ;; Convert raw → DER via the private helper (exercising the converter).
          der (#'bc-secp/raw->der-sig raw)]
      (is (= 64 (count raw)))
      (is (#{70 71 72} (count der)) "DER for secp256k1 is 70-72 bytes")
      (is (sign/verify kp msg raw))
      (is (sign/verify kp msg der)))))

;; -- External fixture (openssl-generated) --
;;
;; Validates we can verify a signature produced by an unrelated ECDSA
;; implementation. Generated one-time via:
;;   openssl ecparam -name secp256k1 -genkey -noout -out priv.pem
;;   openssl ec -in priv.pem -pubout -conv_form compressed \
;;       -outform DER -out pub.der          # last 33 bytes = compressed pubkey
;;   printf 'hello signet secp256k1' > msg.bin
;;   openssl dgst -sha256 -sign priv.pem -out sig.bin msg.bin

(def ^:private fixture-pubkey-hex
  "03c0c02f0b17d527a76c24a32b8280de2ce7288188e18f5435e13589632be42a9d")

(def ^:private fixture-msg-bytes
  (.getBytes "hello signet secp256k1" "UTF-8"))

(def ^:private fixture-sig-der-hex
  (str "3044022010be8f4028dfeea89908095616c5b4301572d02e072e0faf477a29a698f76e89"
       "02200a68a0c0c06df88c5787ad29745ff4d6b9ff7d5bf6daded740135409949550f1"))

(deftest secp256k1-verify-openssl-fixture
  (testing "verifies a known-good DER signature produced by openssl"
    (let [pub-bytes (enc/hex->bytes fixture-pubkey-hex)
          sig-der   (enc/hex->bytes fixture-sig-der-hex)
          pub       (key/signing-keypair :secp256k1 pub-bytes (byte-array 32))]
      (is (= :signet/secp256k1-keypair (:type pub)))
      (is (sign/verify pub fixture-msg-bytes sig-der)))))

(deftest secp256k1-verify-openssl-fixture-tampered
  (testing "rejects the openssl signature against a different message"
    (let [pub-bytes (enc/hex->bytes fixture-pubkey-hex)
          sig-der   (enc/hex->bytes fixture-sig-der-hex)
          pub       (key/signing-keypair :secp256k1 pub-bytes (byte-array 32))
          tampered  (.getBytes "hello signet secp256k1!" "UTF-8")]
      (is (not (sign/verify pub tampered sig-der))))))

;; -- kid URN round-trip --

(deftest secp256k1-kid-round-trip
  (testing "kid URN round-trip for a secp256k1 public key"
    (let [pub-bytes (enc/hex->bytes fixture-pubkey-hex)
          pub       (key/->Secp256k1PublicKey
                     :signet/secp256k1-public-key :secp256k1 pub-bytes)
          urn       (key/kid pub)
          parsed    (key/kid->public-key urn)]
      (is (.startsWith ^String urn "urn:signet:pk:secp256k1:"))
      (is (= :signet/secp256k1-public-key (:type parsed)))
      (is (java.util.Arrays/equals ^bytes pub-bytes ^bytes (:x parsed))))))
