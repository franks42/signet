(ns signet.sign-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.sign :as sign]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; === Low-level sign/verify tests ===

(deftest sign-verify-bytes-test
  (testing "sign and verify round-trip"
    (let [kp (key/signing-keypair)
          msg (.getBytes "hello world" "UTF-8")
          sig (sign/sign kp msg)]
      (is (= 64 (count sig)))
      (is (sign/verify kp msg sig))))

  (testing "verify fails with wrong key"
    (let [kp1 (key/signing-keypair)
          kp2 (key/signing-keypair)
          msg (.getBytes "hello" "UTF-8")
          sig (sign/sign kp1 msg)]
      (is (not (sign/verify kp2 msg sig)))))

  (testing "verify fails with tampered message"
    (let [kp (key/signing-keypair)
          msg (.getBytes "original" "UTF-8")
          sig (sign/sign kp msg)]
      (is (not (sign/verify kp (.getBytes "tampered" "UTF-8") sig)))))

  (testing "sign works with private key record"
    (let [kp (key/signing-keypair)
          priv (key/signing-private-key kp)
          msg (.getBytes "test" "UTF-8")
          sig (sign/sign priv msg)]
      (is (sign/verify kp msg sig))))

  (testing "verify works with public key record"
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)
          msg (.getBytes "test" "UTF-8")
          sig (sign/sign kp msg)]
      (is (sign/verify pub msg sig)))))

;; === High-level sign-edn/verify-edn tests ===

(deftest sign-edn-basic-test
  (testing "sign and verify EDN payload"
    (let [kp (key/signing-keypair)
          payload {:action :transfer :amount 100}
          envelope (sign/sign-edn kp payload)
          result (sign/verify-edn envelope)]
      (is (sign/signed? envelope))
      (is (= :signet/signed (:type envelope)))
      (is (= payload (get-in envelope [:envelope :message])))
      (is (some? (get-in envelope [:envelope :request-id])))
      (is (some? (get-in envelope [:envelope :signer])))
      (is (= 64 (count (:signature envelope))))

      (is (:valid? result))
      (is (= payload (:message result)))
      (is (= (key/kid kp) (:signer result)))
      (is (pos? (:timestamp result)))
      (is (>= (:age-ms result) 0))
      (is (some? (:digest result)))
      (is (some? (:message-digest result))))))

(deftest sign-edn-default-keypair-test
  (testing "sign-edn with no keypair uses default"
    (let [kp (key/signing-keypair)
          envelope (sign/sign-edn {:msg "hello"})
          result (sign/verify-edn envelope)]
      (is (:valid? result))
      (is (= (key/kid kp) (:signer result)))))

  (testing "sign-edn auto-generates keypair if no default"
    (key/clear-key-store!)
    (let [envelope (sign/sign-edn {:msg "hello"})
          result (sign/verify-edn envelope)]
      (is (:valid? result))
      (is (some? (key/default-signing-keypair))))))

(deftest sign-edn-ttl-test
  (testing "sign with TTL sets expiration"
    (let [kp (key/signing-keypair)
          envelope (sign/sign-edn kp {:msg "temp"} {:ttl 3600})
          result (sign/verify-edn envelope)]
      (is (:valid? result))
      (is (some? (:expires result)))
      (is (false? (:expired? result)))
      ;; expires should be ~1 hour from now
      (is (> (:expires result) (:timestamp result)))
      (is (< (- (:expires result) (:timestamp result) 3600000) 100))))

  (testing "expired envelope is flagged"
    (let [kp (key/signing-keypair)
          ;; TTL of 0 seconds = already expired
          envelope (sign/sign-edn kp {:msg "old"} {:ttl 0})]
      (Thread/sleep 10)
      (let [result (sign/verify-edn envelope)]
        (is (:valid? result))
        (is (:expired? result))))))

(deftest sign-edn-tamper-test
  (testing "tampered message fails verification"
    (let [kp (key/signing-keypair)
          envelope (sign/sign-edn kp {:amount 100})
          tampered (assoc-in envelope [:envelope :message :amount] 999)
          result (sign/verify-edn tampered)]
      (is (not (:valid? result)))))

  (testing "tampered signer fails verification"
    (let [kp1 (key/signing-keypair)
          kp2 (key/signing-keypair)
          envelope (sign/sign-edn kp1 {:msg "test"})
          tampered (assoc-in envelope [:envelope :signer] (key/kid kp2))
          result (sign/verify-edn tampered)]
      (is (not (:valid? result))))))

(deftest sign-edn-various-payloads-test
  (testing "string payload"
    (let [kp (key/signing-keypair)
          result (sign/verify-edn (sign/sign-edn kp "hello"))]
      (is (:valid? result))
      (is (= "hello" (:message result)))))

  (testing "nil payload"
    (let [kp (key/signing-keypair)
          result (sign/verify-edn (sign/sign-edn kp nil))]
      (is (:valid? result))
      (is (nil? (:message result)))))

  (testing "vector payload"
    (let [kp (key/signing-keypair)
          result (sign/verify-edn (sign/sign-edn kp [1 2 3]))]
      (is (:valid? result))
      (is (= [1 2 3] (:message result)))))

  (testing "nested map payload"
    (let [kp (key/signing-keypair)
          payload {:user "alice" :perms #{:read :write} :meta {:level 3}}
          result (sign/verify-edn (sign/sign-edn kp payload))]
      (is (:valid? result))
      (is (= payload (:message result))))))

(deftest sign-edn-digest-test
  (testing "same message + different signers produce same message-digest"
    (let [kp1 (key/signing-keypair)
          kp2 (key/signing-keypair)
          payload {:data "shared"}
          r1 (sign/verify-edn (sign/sign-edn kp1 payload))
          r2 (sign/verify-edn (sign/sign-edn kp2 payload))]
      (is (java.util.Arrays/equals ^bytes (:message-digest r1)
                                   ^bytes (:message-digest r2)))))

  (testing "same message + same signer produce different envelope digests"
    (let [kp (key/signing-keypair)
          r1 (sign/verify-edn (sign/sign-edn kp {:data "x"}))
          r2 (sign/verify-edn (sign/sign-edn kp {:data "x"}))]
      ;; Different request-ids → different envelope digests
      (is (not (java.util.Arrays/equals ^bytes (:digest r1)
                                        ^bytes (:digest r2)))))))

(deftest signed-predicate-test
  (testing "signed? predicate"
    (let [kp (key/signing-keypair)]
      (is (sign/signed? (sign/sign-edn kp "test")))
      (is (not (sign/signed? {})))
      (is (not (sign/signed? {:type :other})))
      (is (not (sign/signed? nil))))))

;; === sign-seal tests ===

(deftest sign-seal-basic-test
  (testing "sign-seal produces a sealed envelope"
    (let [envelope (sign/sign-seal {:msg "ephemeral"})
          result (sign/verify-edn envelope)]
      (is (sign/sign-sealed? envelope))
      (is (= :signet/sealed (:type envelope)))
      (is (= {:msg "ephemeral"} (:message result)))
      (is (:valid? result))
      (is (:sealed? result))
      (is (not (:sealed? (sign/verify-edn (sign/sign-edn (key/signing-keypair) "x")))))))

  (testing "sealed envelope signer is discoverable"
    (let [envelope (sign/sign-seal {:msg "test"})
          signer-kid (get-in envelope [:envelope :signer])]
      (is (.startsWith ^String signer-kid "urn:signet:pk:ed25519:"))
      (is (some? (key/lookup signer-kid)))
      ;; Only public key in store, not keypair
      (is (key/signing-public-key? (key/lookup signer-kid))))))

(deftest sign-seal-no-private-key-leak-test
  (testing "ephemeral private key is not in the key store"
    (let [envelope (sign/sign-seal {:secret "data"})
          signer-kid (get-in envelope [:envelope :signer])
          stored-key (key/lookup signer-kid)]
      ;; Public key is registered for verification
      (is (key/signing-public-key? stored-key))
      ;; No private key material
      (is (nil? (:d stored-key)))))

  (testing "each seal uses a different ephemeral key"
    (let [e1 (sign/sign-seal {:n 1})
          e2 (sign/sign-seal {:n 2})]
      (is (not= (get-in e1 [:envelope :signer])
                (get-in e2 [:envelope :signer]))))))

(deftest sign-seal-ttl-test
  (testing "sign-seal with TTL"
    (let [envelope (sign/sign-seal {:msg "temp"} {:ttl 60})
          result (sign/verify-edn envelope)]
      (is (:valid? result))
      (is (some? (:expires result)))
      (is (false? (:expired? result))))))

(deftest sign-seal-tamper-test
  (testing "tampered sealed envelope fails verification"
    (let [envelope (sign/sign-seal {:amount 100})
          tampered (assoc-in envelope [:envelope :message :amount] 999)
          result (sign/verify-edn tampered)]
      (is (not (:valid? result))))))

(deftest sign-seal-predicates-test
  (testing "sign-sealed? vs signed?"
    (let [kp (key/signing-keypair)
          signed (sign/sign-edn kp "test")
          sealed (sign/sign-seal "test")]
      (is (sign/signed? signed))
      (is (not (sign/sign-sealed? signed)))
      (is (sign/sign-sealed? sealed))
      (is (not (sign/signed? sealed))))))
