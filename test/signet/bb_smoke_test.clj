(ns signet.bb-smoke-test
  "Smoke tests that exercise the code paths previously broken under
   babashka — specifically anything that triggers seed->public-key
   derivation via `proxy [SecureRandom]`, which bb's proxy does not
   support for concrete JCA classes.

   Run with `bb smoke` from the signet repo root.

   If this test breaks on bb, it means someone has reintroduced a
   code path that calls `jvm/ed25519-seed->public-key` — which runs
   fine on the JVM but hangs or errors on bb. The fix is usually to
   use already-available public key bytes (e.g., from a keypair
   record's :x field) instead of deriving from the seed."
  (:require [clojure.test :refer [deftest is testing]]
            [signet.key :as key]
            [signet.sign :as sign]
            [signet.chain :as chain]
            [signet.encoding :as enc]))

(deftest keypair-and-kid-round-trip
  (testing "generate → kid → kid->public-key round-trips"
    (let [kp  (key/signing-keypair)
          urn (key/kid kp)
          pub (key/kid->public-key urn)]
      (is (= :signet/ed25519-keypair (:type kp)))
      (is (= 32 (count (:x kp))))
      (is (= 32 (count (:d kp))))
      (is (.startsWith ^String urn "urn:signet:pk:ed25519:"))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub))))))

(deftest sign-edn-round-trip
  (testing "sign-edn + verify-edn (previously broke at signing time)"
    (let [kp       (key/signing-keypair)
          envelope (sign/sign-edn kp {:hello 1 :items [1 2 3]})
          verified (sign/verify-edn envelope)]
      (is (:valid? verified))
      (is (= {:hello 1 :items [1 2 3]} (:message verified)))
      (is (= (key/kid kp) (:signer verified))))))

(deftest sign-edn-with-ttl
  (testing "sign-edn + :ttl option — stores :expires in envelope"
    (let [kp       (key/signing-keypair)
          envelope (sign/sign-edn kp {:action :test} {:ttl 60})
          verified (sign/verify-edn envelope)]
      (is (:valid? verified))
      (is (pos? (:expires verified)))
      (is (false? (:expired? verified))))))

(deftest chain-extend-close-verify
  (testing "full chain lifecycle — create, close, verify
            (this was the original failing path from alpaca-clj)"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp {:facts [[:effect :read]
                                                     [:domain "market"]]})
                      (chain/close))
          result  (chain/verify token)]
      (is (= :signet/chain (:type token)))
      (is (true? (chain/sealed? token)))
      (is (:valid? result))
      (is (:sealed? result))
      (is (= (key/kid root-kp) (:root result)))
      (is (= 1 (count (:blocks result)))))))

(deftest chain-multi-block-verify
  (testing "multi-block chain (delegation) verifies end-to-end"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp {:facts [[:role :admin]]})
                      (chain/extend       {:facts [[:effect :read]]})
                      (chain/close        {:facts [[:domain "market"]]}))
          result  (chain/verify token)]
      (is (:valid? result))
      (is (= 3 (count (:blocks result)))))))

(deftest kid-hex-round-trip
  (testing "kid → hex → kid (the new helper)"
    (let [kp  (key/signing-keypair)
          urn (key/kid kp)
          hex (key/kid->hex urn)]
      (is (= 64 (count hex)))
      (is (= urn (key/hex->kid hex))))))

(deftest hex-byte-round-trip
  (testing "encoding/bytes->hex + hex->bytes preserve byte identity"
    (let [raw (byte-array [0 1 -128 127 -1 42])
          hex (enc/bytes->hex raw)]
      (is (java.util.Arrays/equals raw (enc/hex->bytes hex))))))
