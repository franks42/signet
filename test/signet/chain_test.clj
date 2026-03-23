(ns signet.chain-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.chain :as chain]
            [signet.key :as key]
            [signet.sign :as sign]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; === Chain creation tests ===

(deftest extend-create-test
  (testing "create chain with default signing keypair"
    (let [root-kp (key/signing-keypair)
          token (chain/extend {:facts ["alice can read"]})]
      (is (chain/chain? token))
      (is (chain/open? token))
      (is (not (chain/sealed? token)))
      (is (= (key/kid root-kp) (:root token)))
      (is (= 1 (count (:blocks token))))
      (is (some? (:proof token)))))

  (testing "create chain with explicit root key"
    (let [root-kp (key/signing-keypair)
          token (chain/extend root-kp {:facts ["bob can write"]})]
      (is (chain/chain? token))
      (is (= (key/kid root-kp) (:root token)))))

  (testing "create chain fails without default key"
    (key/clear-key-store!)
    (is (thrown? clojure.lang.ExceptionInfo
                (chain/extend {:facts ["no key"]})))))

;; === Chain extension tests ===

(deftest extend-chain-test
  (testing "extend adds a block"
    (let [root-kp (key/signing-keypair)
          token (chain/extend {:facts ["alice can read/write"]})
          token2 (chain/extend token {:checks ["only read"]})]
      (is (= 2 (count (:blocks token2))))
      (is (chain/open? token2))))

  (testing "multiple extensions"
    (let [_root (key/signing-keypair)
          token (-> (chain/extend {:facts ["broad access"]})
                    (chain/extend {:checks ["narrow 1"]})
                    (chain/extend {:checks ["narrow 2"]})
                    (chain/extend {:checks ["narrow 3"]}))]
      (is (= 4 (count (:blocks token))))
      (is (chain/open? token))))

  (testing "cannot extend a sealed chain"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (thrown? clojure.lang.ExceptionInfo
                  (chain/extend sealed {:checks ["nope"]}))))))

;; === Chain sealing tests ===

(deftest close-test
  (testing "close seals the chain"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (chain/sealed? sealed))
      (is (not (chain/open? sealed)))
      (is (map? (:proof sealed)))
      (is (true? (get-in sealed [:proof :sealed])))))

  (testing "close with content adds block then seals"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["broad"]})
                     (chain/close {:checks ["final restriction"]}))]
      (is (chain/sealed? sealed))
      (is (= 2 (count (:blocks sealed))))))

  (testing "cannot seal an already sealed chain"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (thrown? clojure.lang.ExceptionInfo
                  (chain/close sealed))))))

;; === Chain verification tests ===

(deftest verify-sealed-test
  (testing "verify a simple sealed chain"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["alice can read"]})
                     (chain/close))
          result (chain/verify sealed)]
      (is (:valid? result))
      (is (:sealed? result))
      (is (some? (:root result)))
      (is (= 1 (count (:blocks result))))))

  (testing "verify a multi-block sealed chain"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["alice can read/write"]})
                     (chain/extend {:checks ["only read"]})
                     (chain/extend {:checks ["only /data/reports/*"]})
                     (chain/close {:checks ["only q1.csv"]}))
          result (chain/verify sealed)]
      (is (:valid? result))
      (is (:sealed? result))
      (is (= 4 (count (:blocks result))))
      ;; Check the content is preserved in order
      (is (= {:facts ["alice can read/write"]}
             (:data (first (:blocks result)))))
      (is (= {:checks ["only q1.csv"]}
             (:data (last (:blocks result))))))))

(deftest verify-open-test
  (testing "verify an open chain"
    (let [_root (key/signing-keypair)
          token (-> (chain/extend {:facts ["test"]})
                    (chain/extend {:checks ["check 1"]}))
          result (chain/verify token)]
      (is (:valid? result))
      (is (not (:sealed? result))))))

(deftest verify-tamper-test
  (testing "tampered block content fails"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["alice can read"]})
                     (chain/close))
          ;; Tamper with block 0's message
          tampered (assoc-in sealed [:blocks 0 :envelope :message :data]
                             {:facts ["alice can ADMIN"]})]
      (is (not (:valid? (chain/verify tampered))))))

  (testing "removed block fails"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["block 0"]})
                     (chain/extend {:checks ["block 1"]})
                     (chain/close))
          ;; Remove the middle block
          tampered (update sealed :blocks #(vec (take 1 %)))]
      ;; Seal proof won't match since we removed blocks
      (is (not (:valid? (chain/verify tampered))))))

  (testing "reordered blocks fail"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["block 0"]})
                     (chain/extend {:checks ["block 1"]})
                     (chain/extend {:checks ["block 2"]})
                     (chain/close))
          ;; Swap blocks 1 and 2
          tampered (assoc sealed :blocks
                         [(get-in sealed [:blocks 0])
                          (get-in sealed [:blocks 2])
                          (get-in sealed [:blocks 1])])]
      (is (not (:valid? (chain/verify tampered))))))

  (testing "wrong root key fails"
    (let [_root (key/signing-keypair)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))
          ;; Change the root to a different key
          other-kp (key/signing-keypair)
          tampered (assoc sealed :root (key/kid other-kp))]
      (is (not (:valid? (chain/verify tampered)))))))

;; === Predicate tests ===

(deftest predicate-test
  (testing "chain?"
    (let [_root (key/signing-keypair)]
      (is (chain/chain? (chain/extend {:x 1})))
      (is (not (chain/chain? {})))
      (is (not (chain/chain? nil)))))

  (testing "open? and sealed?"
    (let [_root (key/signing-keypair)
          open (chain/extend {:x 1})
          sealed (chain/close open)]
      (is (chain/open? open))
      (is (not (chain/sealed? open)))
      (is (chain/sealed? sealed))
      (is (not (chain/open? sealed))))))

;; === End-to-end scenario ===

(deftest e2e-bearer-token-test
  (testing "full bearer token flow: issue → attenuate → attenuate → seal → verify"
    (let [;; Admin establishes identity
          admin-kp (key/signing-keypair)

          ;; Admin issues broad capability
          token (chain/extend admin-kp
                              {:subject "alice"
                               :rights  [:read :write]
                               :resource "/data/*"})

          ;; Alice attenuates: read-only
          token (chain/extend token
                              {:restrict [:read-only]
                               :resource "/data/reports/*"})

          ;; Report service attenuates further and seals
          sealed (chain/close token
                              {:resource "/data/reports/q1.csv"
                               :expires  1711003600000})

          ;; Verifier checks the sealed token
          result (chain/verify sealed)]

      ;; Chain is valid and sealed
      (is (:valid? result))
      (is (:sealed? result))

      ;; Root authority is the admin
      (is (= (key/kid admin-kp) (:root result)))

      ;; All three blocks are present with correct content
      (is (= 3 (count (:blocks result))))
      (is (= "alice" (get-in (first (:blocks result)) [:data :subject])))
      (is (= [:read-only] (get-in (second (:blocks result)) [:data :restrict])))
      (is (= "/data/reports/q1.csv"
             (get-in (last (:blocks result)) [:data :resource]))))))
