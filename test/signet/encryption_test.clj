(ns signet.encryption-test
  "Tests for sender-authenticated AEAD encryption between signet
   identities. JVM-only (uses ChaCha20-Poly1305 via JCA, in JDK 11+
   and bb-compatible)."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encryption :as enc]
            [signet.key :as key]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; ---- Roundtrip ----

(deftest box-unbox-roundtrip-x25519
  (testing "X25519 keypairs encrypt and decrypt cleanly"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (.getBytes "hello signet" "UTF-8")
          ct    (enc/box alice bob msg)]
      (is (java.util.Arrays/equals msg (enc/unbox bob alice ct))))))

(deftest box-unbox-roundtrip-ed25519
  (testing "Ed25519 keypairs work via auto-conversion to X25519"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          msg   (.getBytes "cross-curve hello" "UTF-8")
          ct    (enc/box alice bob msg)]
      (is (java.util.Arrays/equals msg (enc/unbox bob alice ct))))))

(deftest box-unbox-large-message
  (testing "10KB roundtrip"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (byte-array (take 10240 (cycle [0 1 2 -1 127 -128 42])))
          ct    (enc/box alice bob msg)]
      (is (java.util.Arrays/equals msg (enc/unbox bob alice ct))))))

(deftest box-empty-message
  (testing "zero-length plaintext is valid"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (byte-array 0)
          ct    (enc/box alice bob msg)]
      (is (java.util.Arrays/equals msg (enc/unbox bob alice ct))))))

;; ---- Wire format ----

(deftest ciphertext-format
  (testing "ciphertext = 12-byte nonce + ciphertext-with-tag"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (.getBytes "x" "UTF-8")
          ct    (enc/box alice bob msg)]
      ;; 12 nonce + 1 plaintext + 16 tag = 29 bytes
      (is (= 29 (count ct))))))

(deftest nonces-are-unique
  (testing "successive boxes use different nonces (random)"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (.getBytes "same" "UTF-8")
          ct1   (enc/box alice bob msg)
          ct2   (enc/box alice bob msg)
          n1    (java.util.Arrays/copyOfRange ct1 0 12)
          n2    (java.util.Arrays/copyOfRange ct2 0 12)]
      (is (not (java.util.Arrays/equals n1 n2))))))

;; ---- Negative cases ----

(deftest unbox-rejects-tampered-ciphertext
  (testing "flipped byte → AEAD auth fails"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (.getBytes "tamper-test" "UTF-8")
          ct    (enc/box alice bob msg)
          ;; Flip a byte in the ciphertext body (not the nonce header).
          _     (aset-byte ct 20 (unchecked-byte (bit-xor (aget ct 20) 0xff)))]
      (is (thrown? Exception (enc/unbox bob alice ct))))))

(deftest unbox-rejects-wrong-sender-pub
  (testing "decrypting with the wrong sender pubkey fails"
    (let [alice    (key/encryption-keypair)
          bob      (key/encryption-keypair)
          imposter (key/encryption-keypair)
          msg      (.getBytes "for bob" "UTF-8")
          ct       (enc/box alice bob msg)]
      (is (thrown? Exception (enc/unbox bob imposter ct))))))

(deftest unbox-rejects-wrong-recipient-priv
  (testing "decrypting with the wrong recipient private key fails"
    (let [alice    (key/encryption-keypair)
          bob      (key/encryption-keypair)
          eve      (key/encryption-keypair)
          msg     (.getBytes "for bob only" "UTF-8")
          ct       (enc/box alice bob msg)]
      (is (thrown? Exception (enc/unbox eve alice ct))))))

(deftest unbox-rejects-truncated-ciphertext
  (testing "ciphertext shorter than 28 bytes (12 nonce + ≥16 tag) rejected"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"ciphertext too short"
                            (enc/unbox bob alice (byte-array 10)))))))

;; ---- AAD (additional authenticated data) ----

(deftest aad-bound-to-ciphertext
  (testing "matching AAD round-trips, mismatched AAD fails"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg   (.getBytes "with aad" "UTF-8")
          aad   (.getBytes "ceremony-id-42" "UTF-8")
          ct    (enc/box alice bob msg {:aad aad})]
      (is (java.util.Arrays/equals msg (enc/unbox bob alice ct {:aad aad})))
      ;; Wrong AAD → auth fails.
      (is (thrown? Exception
                   (enc/unbox bob alice ct {:aad (.getBytes "wrong-context" "UTF-8")})))
      ;; Missing AAD when encrypted with one → auth fails.
      (is (thrown? Exception (enc/unbox bob alice ct))))))

;; ---- Symmetric DH property ----

(deftest box-symmetric-on-shared-secret
  (testing "Alice's box from Bob is decryptable by Bob from Alice (DH symmetry)"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          msg-a→b (.getBytes "alice to bob" "UTF-8")
          msg-b→a (.getBytes "bob to alice" "UTF-8")]
      (is (java.util.Arrays/equals msg-a→b
                                   (enc/unbox bob alice (enc/box alice bob msg-a→b))))
      (is (java.util.Arrays/equals msg-b→a
                                   (enc/unbox alice bob (enc/box bob alice msg-b→a)))))))
