(ns signet.chain-test
  (:require [cedn.core :as cedn]
            [clojure.edn :as edn]
            [clojure.string]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.chain :as chain]
            [signet.key :as key]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (vault/reset-default-vault!) (f)))

;; === Chain creation tests ===

(deftest extend-create-test
  (testing "create chain with default signing keypair"
    (let [root-kp (vault/ensure-default-signing-key!)
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

  (testing "create chain fails without default key, with a typed error"
    (vault/reset-default-vault!)
    (is (= :signet.chain/no-default-signing-keypair
           (try (chain/extend {:facts ["no key"]}) :no-throw
                (catch clojure.lang.ExceptionInfo e (:type (ex-data e))))))
    (key/signing-keypair)
    (is (thrown? clojure.lang.ExceptionInfo (chain/extend {:facts ["still none"]}))
        "creating a keypair (pure) does not make it the default")))

;; === Chain extension tests ===

(deftest extend-chain-test
  (testing "extend adds a block"
    (let [_ (vault/ensure-default-signing-key!) ; the default root key extend uses
          token (chain/extend {:facts ["alice can read/write"]})
          token2 (chain/extend token {:checks ["only read"]})]
      (is (= 2 (count (:blocks token2))))
      (is (chain/open? token2))))

  (testing "multiple extensions"
    (let [_root (vault/ensure-default-signing-key!)
          token (-> (chain/extend {:facts ["broad access"]})
                    (chain/extend {:checks ["narrow 1"]})
                    (chain/extend {:checks ["narrow 2"]})
                    (chain/extend {:checks ["narrow 3"]}))]
      (is (= 4 (count (:blocks token))))
      (is (chain/open? token))))

  (testing "cannot extend a sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (chain/extend sealed {:checks ["nope"]}))))))

;; === Chain sealing tests ===

(deftest close-test
  (testing "close seals the chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (chain/sealed? sealed))
      (is (not (chain/open? sealed)))
      (is (map? (:proof sealed)))
      (is (true? (get-in sealed [:proof :sealed])))))

  (testing "close with content adds block then seals"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["broad"]})
                     (chain/close {:checks ["final restriction"]}))]
      (is (chain/sealed? sealed))
      (is (= 2 (count (:blocks sealed))))))

  (testing "cannot seal an already sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (chain/close sealed))))))

;; === Chain verification tests ===

(deftest verify-sealed-test
  (testing "verify a simple sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["alice can read"]})
                     (chain/close))
          result (chain/verify sealed)]
      (is (:valid? result))
      (is (:sealed? result))
      (is (some? (:root result)))
      (is (= 1 (count (:blocks result))))))

  (testing "verify a multi-block sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
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
    (let [_root (vault/ensure-default-signing-key!)
          token (-> (chain/extend {:facts ["test"]})
                    (chain/extend {:checks ["check 1"]}))
          result (chain/verify token)]
      (is (:valid? result))
      (is (not (:sealed? result))))))

(deftest verify-tamper-test
  (testing "tampered block content fails"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["alice can read"]})
                     (chain/close))
          ;; Tamper with block 0's message
          tampered (assoc-in sealed [:blocks 0 :envelope :message :data]
                             {:facts ["alice can ADMIN"]})]
      (is (not (:valid? (chain/verify tampered))))))

  (testing "removed block fails"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["block 0"]})
                     (chain/extend {:checks ["block 1"]})
                     (chain/close))
          ;; Remove the middle block
          tampered (update sealed :blocks #(vec (take 1 %)))]
      ;; Seal proof won't match since we removed blocks
      (is (not (:valid? (chain/verify tampered))))))

  (testing "reordered blocks fail"
    (let [_root (vault/ensure-default-signing-key!)
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
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]})
                     (chain/close))
          ;; Change the root to a different key
          other-kp (key/signing-keypair)
          tampered (assoc sealed :root (key/kid other-kp))]
      (is (not (:valid? (chain/verify tampered)))))))

;; === Predicate tests ===

(deftest predicate-test
  (testing "chain?"
    (let [_root (vault/ensure-default-signing-key!)]
      (is (chain/chain? (chain/extend {:x 1})))
      (is (not (chain/chain? {})))
      (is (not (chain/chain? nil)))))

  (testing "open? and sealed?"
    (let [_root (vault/ensure-default-signing-key!)
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

;; === Third-party block tests ===

(deftest third-party-request-test
  (testing "third-party-request returns prev-sig binding"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["block 0"]})
          request (chain/third-party-request token)]
      (is (= :signet/third-party-request (:type request)))
      (is (some? (:prev-sig request)))
      (is (bytes? (:prev-sig request)))))

  (testing "third-party-request fails on sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]}) (chain/close))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (chain/third-party-request sealed))))))

(deftest create-third-party-block-test
  (testing "create-third-party-block produces signed block"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["block 0"]})
          request (chain/third-party-request token)
          idp-kp (key/signing-keypair)
          tp-block (chain/create-third-party-block
                    request
                    {:email "alice@idp.com" :role "engineer"}
                    idp-kp)]
      (is (= :signet/third-party-block (:type tp-block)))
      (is (= {:email "alice@idp.com" :role "engineer"} (:data tp-block)))
      (is (some? (:external-sig tp-block)))
      (is (= (key/kid idp-kp) (:external-key tp-block))))))

(deftest extend-third-party-test
  (testing "extend-third-party appends block to chain"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["authority block"]})
          idp-kp (key/signing-keypair)
          request (chain/third-party-request token)
          tp-block (chain/create-third-party-block
                    request {:email "alice@idp.com"} idp-kp)
          token2 (chain/extend-third-party token tp-block)]
      (is (= 2 (count (:blocks token2))))
      (is (chain/open? token2))))

  (testing "can extend further after third-party block"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["authority"]})
          idp-kp (key/signing-keypair)
          request (chain/third-party-request token)
          tp-block (chain/create-third-party-block
                    request {:email "alice@idp.com"} idp-kp)
          token2 (chain/extend-third-party token tp-block)
          token3 (chain/extend token2 {:checks ["only read"]})]
      (is (= 3 (count (:blocks token3))))))

  (testing "extend-third-party fails on sealed chain"
    (let [_root (vault/ensure-default-signing-key!)
          sealed (-> (chain/extend {:facts ["test"]}) (chain/close))
          idp-kp (key/signing-keypair)
          ;; Can't even get a request from sealed, but try extend directly
          tp-block {:type :signet/third-party-block
                    :data {:x 1}
                    :external-sig (byte-array 64)
                    :external-key (key/kid idp-kp)}]
      (is (thrown? clojure.lang.ExceptionInfo
                   (chain/extend-third-party sealed tp-block))))))

(deftest verify-third-party-test
  (testing "chain with third-party block verifies"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["authority"]})
          idp-kp (key/signing-keypair)
          request (chain/third-party-request token)
          tp-block (chain/create-third-party-block
                    request {:email "alice@idp.com"} idp-kp)
          token2 (chain/extend-third-party token tp-block)
          sealed (chain/close token2)
          result (chain/verify sealed)]
      (is (:valid? result))
      (is (= 2 (count (:blocks result))))))

  (testing "tampered third-party content fails verification"
    (let [_root (vault/ensure-default-signing-key!)
          token (chain/extend {:facts ["authority"]})
          idp-kp (key/signing-keypair)
          request (chain/third-party-request token)
          tp-block (chain/create-third-party-block
                    request {:email "alice@idp.com"} idp-kp)
          token2 (chain/extend-third-party token tp-block)
          sealed (chain/close token2)
          ;; Tamper with the third-party block's data
          tampered (assoc-in sealed [:blocks 1 :envelope :message :data]
                             {:email "mallory@evil.com"})]
      (is (not (:valid? (chain/verify tampered))))))

  (testing "third-party block with wrong prev-sig binding fails"
    (let [root-kp (vault/ensure-default-signing-key!)
          token-a (chain/extend {:facts ["chain A"]})
          token-b (chain/extend root-kp {:facts ["chain B"]})
          idp-kp (key/signing-keypair)
          ;; Get request from chain A
          request-a (chain/third-party-request token-a)
          ;; Third party signs for chain A
          tp-block (chain/create-third-party-block
                    request-a {:email "alice@idp.com"} idp-kp)
          ;; Try to append to chain B (different prev-sig)
          token-b2 (chain/extend-third-party token-b tp-block)
          sealed (chain/close token-b2)]
      ;; External sig should fail because it was bound to chain A's prev-sig
      (is (not (:valid? (chain/verify sealed)))))))

(deftest chain-errors-are-typed
  (let [_      (vault/ensure-default-signing-key!)
        sealed (chain/close (chain/extend {:facts ["x"]}))
        type-of (fn [f] (try (f) :no-throw
                             (catch clojure.lang.ExceptionInfo e (:type (ex-data e)))))]
    (is (= :signet.chain/sealed (type-of #(chain/extend sealed {:more 1}))))
    (is (= :signet.chain/sealed (type-of #(chain/close sealed))))
    (is (= :signet.chain/sealed (type-of #(chain/third-party-request sealed))))
    (is (= :signet.chain/bad-argument (type-of #(chain/extend {:type :nope} {:c 1}))))))

;; === Proofs live in the vault (0.8.0) ===

(def ^:private ack {:i-understand :exposes-secret})

(defn- type-of [f]
  (try (f) :no-throw (catch clojure.lang.ExceptionInfo e (:type (ex-data e)))))

(deftest open-proofs-are-vault-handles
  (let [root  (vault/ensure-default-signing-key!)
        token (chain/extend root {:facts ["x"]})
        proof (:proof token)]
    (is (vault/handle? proof))
    (is (some? (vault/handle (:kid proof))) "the vault holds the ephemeral key")
    (is (= (:kid proof) (get-in (peek (:blocks token)) [:envelope :message :next-key]))
        "the proof is the key the last block names")
    (let [seed (vault/export-secret proof ack)
          hex  (apply str (map #(format "%02x" (bit-and % 0xff)) seed))]
      (is (not (clojure.string/includes? (pr-str token) hex)) "printing shows no seed")
      (is (not (clojure.string/includes? (cedn/canonical-str token) hex)) "serialising shows no seed"))
    (is (:valid? (chain/verify token {:root (:kid root)})))))

(deftest sending-and-receiving-a-token
  (let [_       (vault/ensure-default-signing-key!)
        token   (chain/extend {:facts ["alice can read"]})
        wire    (chain/export-token token ack)]
    (is (= :signet.vault/export-not-acknowledged (type-of #(chain/export-token token {}))))
    (is (bytes? (:proof wire)) "the sendable form carries the seed")
    (is (:valid? (chain/verify wire)) "and verifies")
    (testing "the receiver imports it into their own vault"
      (vault/register-vault! :bob)
      (try
        (let [received (chain/import-token! :bob (edn/read-string {:readers cedn/readers} (cedn/canonical-str wire)))]
          (is (vault/handle? (:proof received)))
          (is (= :bob (:vault (:proof received))))
          (is (:valid? (chain/verify received)))
          (let [narrowed (chain/extend received {:checks ["read only"]})]
            (is (:valid? (chain/verify narrowed)))
            (is (= :bob (:vault (:proof narrowed))) "new proofs stay in the receiver's vault")))
        (finally (vault/unregister-vault! :bob))))
    (testing "the sendable form can also be extended directly"
      (is (:valid? (chain/verify (chain/extend wire {:checks ["c"]})))))))

(deftest import-refuses-a-proof-that-does-not-match
  (let [_     (vault/ensure-default-signing-key!)
        wire  (chain/export-token (chain/extend {:f 1}) ack)
        other (chain/export-token (chain/extend {:f 2}) ack)
        bad   (assoc wire :proof (:proof other))]
    (is (= :signet.chain/proof-mismatch (type-of #(chain/import-token! bad))))
    (is (false? (:valid? (chain/verify bad))) "and verify rejects it too")))

(deftest close-and-discard-destroy-the-proof
  (let [_     (vault/ensure-default-signing-key!)
        token (chain/extend {:facts ["x"]})
        kid   (:kid (:proof token))
        sealed (chain/close token)]
    (is (chain/sealed? sealed))
    (is (nil? (vault/handle kid)) "sealing destroyed the ephemeral key")
    (is (:valid? (chain/verify sealed))))
  (let [token (chain/extend {:facts ["y"]})
        kid   (:kid (:proof token))]
    (chain/discard! token)
    (is (nil? (vault/handle kid)))
    (is (= :signet.vault/destroyed-key (type-of #(chain/extend token {:c 1})))
        "a discarded token can no longer be extended")))

(deftest one-token-narrowed-two-ways
  (let [_    (vault/ensure-default-signing-key!)
        base (chain/extend {:facts ["broad"]})
        a    (chain/extend base {:checks ["for a"]})
        b    (chain/extend base {:checks ["for b"]})]
    (is (:valid? (chain/verify a)))
    (is (:valid? (chain/verify b)))
    (is (not= (:kid (:proof a)) (:kid (:proof b))))))

(deftest verify-checks-the-proof-handle-names-the-right-key
  (let [_     (vault/ensure-default-signing-key!)
        token (chain/extend {:facts ["x"]})
        swapped (assoc token :proof (vault/generate-signing-key!))]
    (is (:valid? (chain/verify token)))
    (is (false? (:valid? (chain/verify swapped))) "a handle for another key is not the proof")))
