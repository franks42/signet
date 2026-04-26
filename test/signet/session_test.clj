(ns signet.session-test
  "Tests for signet.session: Noise_KK forward-secret sessions.

   Each test sets up two parties (alice as initiator, bob as responder)
   with mutual knowledge of each other's static public keys, drives a
   handshake, and exercises transport messages. Uses Ed25519 keypairs
   in most cases since that's the consumer pattern (mpc-multi-signature
   uses long-term Ed25519 identities with auto-conversion to X25519)."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.session :as session]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; ---- Helpers ----

(defn- bytes= [a b]
  (java.util.Arrays/equals ^bytes a ^bytes b))

(defn- run-handshake
  "Drive the two-message KK handshake to completion. Returns the
   handshake-final states for each side plus the application payloads
   each side received from its peer."
  [alice-init bob-resp init-payload resp-payload]
  (let [[alice-1 msg1]    (session/write-message alice-init init-payload)
        [bob-1   pt-init] (session/read-message  bob-resp msg1)
        [bob-2   msg2]    (session/write-message bob-1 resp-payload)
        [alice-2 pt-resp] (session/read-message  alice-1 msg2)]
    {:alice    alice-2
     :bob      bob-2
     :init-pt  pt-init
     :resp-pt  pt-resp
     :msg1     msg1
     :msg2     msg2}))

;; ---- Handshake roundtrip ----

(deftest handshake-roundtrip-ed25519
  (testing "two Ed25519 identities complete a KK handshake"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          init-payload (.getBytes "init payload" "UTF-8")
          resp-payload (.getBytes "resp payload" "UTF-8")
          {:keys [alice bob init-pt resp-pt]} (run-handshake ai br init-payload resp-payload)]
      (is (session/established? alice))
      (is (session/established? bob))
      (is (bytes= init-payload init-pt))
      (is (bytes= resp-payload resp-pt)))))

(deftest handshake-roundtrip-x25519
  (testing "two native X25519 keypairs complete a KK handshake"
    (let [alice (key/encryption-keypair)
          bob   (key/encryption-keypair)
          ai    (session/initiator alice (key/encryption-public-key bob))
          br    (session/responder bob   (key/encryption-public-key alice))
          {:keys [alice bob]} (run-handshake ai br
                                             (.getBytes "a" "UTF-8")
                                             (.getBytes "b" "UTF-8"))]
      (is (session/established? alice))
      (is (session/established? bob)))))

(deftest handshake-empty-payloads
  (testing "handshake messages may carry no application data"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          {:keys [alice bob init-pt resp-pt]}
          (run-handshake ai br (byte-array 0) (byte-array 0))]
      (is (session/established? alice))
      (is (session/established? bob))
      (is (zero? (alength ^bytes init-pt)))
      (is (zero? (alength ^bytes resp-pt))))))

(deftest handshake-with-prologue
  (testing "matching prologues complete; mismatched ones fail"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          good  (.getBytes "ceremony-id-foo" "UTF-8")
          bad   (.getBytes "ceremony-id-bar" "UTF-8")]
      (testing "matching prologue succeeds"
        (let [ai (session/initiator alice (key/signing-public-key bob) {:prologue good})
              br (session/responder bob   (key/signing-public-key alice) {:prologue good})
              {:keys [alice bob]} (run-handshake ai br
                                                 (byte-array 0) (byte-array 0))]
          (is (session/established? alice))
          (is (session/established? bob))))
      (testing "mismatched prologue causes message-1 read to fail"
        (let [ai (session/initiator alice (key/signing-public-key bob) {:prologue good})
              br (session/responder bob   (key/signing-public-key alice) {:prologue bad})
              [_ai m1] (session/write-message ai (byte-array 0))]
          (is (thrown? Exception (session/read-message br m1))))))))

;; ---- Transport ----

(deftest transport-roundtrip-bidirectional
  (testing "after handshake, both sides can send transport messages"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          {:keys [alice bob]} (run-handshake ai br
                                             (byte-array 0) (byte-array 0))
          msg-a    (.getBytes "alice → bob 1" "UTF-8")
          msg-b    (.getBytes "bob → alice 1" "UTF-8")
          [alice ct1] (session/write-message alice msg-a)
          [bob   pt1] (session/read-message  bob ct1)
          [bob   ct2] (session/write-message bob msg-b)
          [alice pt2] (session/read-message  alice ct2)]
      (is (bytes= msg-a pt1))
      (is (bytes= msg-b pt2)))))

(deftest transport-multiple-messages
  (testing "nonce counters increment correctly across many transport msgs"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          {alice :alice bob :bob} (run-handshake ai br
                                                 (byte-array 0) (byte-array 0))]
      (loop [alice alice
             bob   bob
             i     0]
        (when (< i 64)
          (let [pt (.getBytes (str "msg-" i) "UTF-8")
                [alice' ct]  (session/write-message alice pt)
                [bob'   got] (session/read-message  bob ct)]
            (is (bytes= pt got))
            (recur alice' bob' (inc i))))))))

;; ---- Failure modes ----

(deftest tampered-handshake-msg1-fails
  (testing "flipping a byte of msg1 causes responder's read to throw"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          [_ai m1] (session/write-message ai (.getBytes "hi" "UTF-8"))
          tampered (let [bs (aclone ^bytes m1)]
                     (aset-byte bs 40 (unchecked-byte (bit-xor (aget bs 40) 0xff)))
                     bs)]
      (is (thrown? Exception (session/read-message br tampered))))))

(deftest tampered-transport-fails
  (testing "flipping a byte of a transport ciphertext causes recv to throw"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          {:keys [alice bob]} (run-handshake ai br
                                             (byte-array 0) (byte-array 0))
          [_alice ct] (session/write-message alice (.getBytes "secret" "UTF-8"))
          tampered    (let [bs (aclone ^bytes ct)]
                        (aset-byte bs 0 (unchecked-byte (bit-xor (aget bs 0) 0xff)))
                        bs)]
      (is (thrown? Exception (session/read-message bob tampered))))))

(deftest wrong-remote-static-fails
  (testing "responder using the wrong claimed initiator-static rejects msg1"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          eve   (key/signing-keypair) ; wrong identity
          ai    (session/initiator alice (key/signing-public-key bob))
          ;; bob expects eve, not alice. The 'ss' DH on each side will
          ;; produce different outputs, so the AEAD on msg 1's payload
          ;; fails to decrypt.
          br-wrong (session/responder bob (key/signing-public-key eve))
          [_ai m1] (session/write-message ai (.getBytes "hi" "UTF-8"))]
      (is (thrown? Exception (session/read-message br-wrong m1))))))

(deftest wrong-message-phase-fails
  (testing "calling write-message on a state that should read raises"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          br    (session/responder bob (key/signing-public-key alice))]
      ;; Responder must read msg1 first; calling write-message at pos 0
      ;; (responder's responsibility is to wait) raises.
      (is (thrown-with-msg? Exception
                            #"wrong phase"
                            (session/write-message br (byte-array 0)))))))

(deftest truncated-handshake-message-fails
  (testing "a too-short msg1 raises with a clear reason"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          br    (session/responder bob (key/signing-public-key alice))]
      (is (thrown-with-msg? Exception
                            #"too short"
                            (session/read-message br (byte-array 10)))))))

;; ---- Forward secrecy property ----

(deftest forward-secrecy-via-distinct-ephemerals
  (testing "two sessions between the same parties produce different transport keys"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          run-once
          (fn []
            (let [ai (session/initiator alice (key/signing-public-key bob))
                  br (session/responder bob   (key/signing-public-key alice))
                  {alice :alice} (run-handshake ai br (byte-array 0) (byte-array 0))]
              ;; Pull the transport send key out for comparison.
              (-> alice :send :k vec)))
          k1 (run-once)
          k2 (run-once)]
      (is (not= k1 k2)
          "two sessions with same long-term keys should derive different session keys"))))
