(ns signet.shared-test
  "Shared symmetric keys kept in the vault (decisions 14 and 16): both sides
   derive the same key and kid with no exchange, seal/open is directional
   and key-committing, MACs are directional, nothing secret on any output."
  (:require [cedn.core :as cedn]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.shared :as shared]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f]
                      (key/clear-key-store!)
                      (vault/reset-default-vault!)
                      (vault/register-vault! :alice)
                      (vault/register-vault! :bob)
                      (try (f)
                           (finally (vault/unregister-vault! :alice)
                                    (vault/unregister-vault! :bob)))))

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))
(defn- text [r] (some-> ^bytes (:plaintext r) (String. "UTF-8")))
(defn- flip ^bytes [^bytes bs]
  (let [c (aclone bs)] (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c))

(defn- pair
  "Alice and Bob, each with a key in their own vault, and the shared key each
   derives from the other's public key."
  ([] (pair nil))
  ([context]
   (let [a  (vault/generate-encryption-key! :alice)
         b  (vault/generate-signing-key! :bob)
         ab (shared/shared-key! a (vault/public-key b) {:context context})
         ba (shared/shared-key! b (vault/public-key a) {:context context})]
     {:a a :b b :ab ab :ba ba})))

(deftest both-sides-derive-the-same-kid-without-exchanging-anything
  (let [{:keys [ab ba]} (pair "app/v1")]
    (is (str/starts-with? (:kid ab) "urn:signet:shared:"))
    (is (= (:kid ab) (:kid ba)))
    (is (= :alice (:vault ab)))
    (is (= :bob (:vault ba)))
    (let [{:keys [a b]} (pair "app/v1")]
      (testing "the context is part of the key"
        (is (not= (:kid (shared/shared-key! a (vault/public-key b) {:context "app/v1"}))
                  (:kid (shared/shared-key! a (vault/public-key b) {:context "app/v2"})))))
      (testing "deriving again gives an equal handle"
        (is (= (shared/shared-key! a (vault/public-key b) {:context "app/v1"})
               (shared/shared-key! a (vault/public-key b) {:context "app/v1"}))))
      (testing "the peer may be named by kid"
        (is (= (shared/shared-key! a (vault/public-key b))
               (shared/shared-key! a (:kid b))))))))

(deftest seal-and-open
  (let [{:keys [ab ba]} (pair)
        sealed (shared/seal ab (utf8 "hello bob") {:aad {:req 7}})]
    (is (= :signet/sealed (:type sealed)))
    (is (= (:kid ab) (:kid sealed)))
    (is (= "hello bob" (text (shared/open ba sealed))))
    (is (= {:req 7} (:aad (shared/open ba sealed))))
    (is (true? (:valid? (shared/open ba sealed {:aad {:req 7}}))))
    (is (= :aad-mismatch (:error (shared/open ba sealed {:aad {:req 8}}))))
    (testing "it is plain EDN: survives canonical text"
      (is (= "hello bob" (text (shared/open ba (edn/read-string {:readers cedn/readers}
                                                                (cedn/canonical-str sealed)))))))
    (testing "and the other way"
      (is (= "hi alice" (text (shared/open ab (shared/seal ba (utf8 "hi alice")))))))))

(deftest seals-cannot-be-reflected
  (let [{:keys [ab]} (pair)
        sealed (shared/seal ab (utf8 "transfer 100 to bob"))]
    (is (false? (:valid? (shared/open ab sealed)))
        "Alice cannot read her own seal as if Bob had sent it")))

(deftest tampering-and-commitment
  (let [{:keys [ab ba]} (pair)
        sealed (shared/seal ab (utf8 "original") {:aad {:n 1}})]
    (doseq [[label s expected] [["ct" (update sealed :ct flip) :authentication-failed]
                                ["nonce" (update sealed :nonce flip) :commitment-mismatch]
                                ["commit" (update sealed :commit flip) :commitment-mismatch]
                                ["aad" (assoc sealed :aad {:n 2}) :authentication-failed]
                                ["extra slot" (assoc sealed :x 1) :unknown-slot]
                                ["version" (assoc sealed :v 2) :unsupported-version]]]
      (is (= expected (:error (shared/open ba s))) label))
    (testing "a different shared key is refused by kid, not tried"
      (let [{other :ba} (pair "other")]
        (is (= :wrong-key (:error (shared/open other sealed))))))))

(deftest open-never-throws
  (let [{:keys [ba]} (pair)]
    (doseq [bad [nil {} "x" {:type :signet/sealed :v 1} (byte-array 3)]]
      (is (false? (:valid? (shared/open ba bad))) (pr-str bad)))))

(deftest macs-are-directional
  (let [{:keys [ab ba]} (pair)
        msg (utf8 "pay 5")
        tag (shared/mac ab msg)]
    (is (= 32 (alength ^bytes tag)))
    (is (true? (shared/verify-mac? ba msg tag)) "Bob verifies Alice's tag")
    (is (false? (shared/verify-mac? ba (utf8 "pay 6") tag)))
    (is (false? (shared/verify-mac? ab msg tag)) "Alice's own tag is not Bob's")
    (is (false? (shared/verify-mac? ba msg (flip tag))))
    (is (false? (shared/verify-mac? ba msg "not bytes")) "never throws")))

(deftest nothing-secret-on-any-output
  (let [{:keys [ab]} (pair)
        root (vault/export-secret ab {:i-understand :exposes-secret})
        hex  (apply str (map #(format "%02x" (bit-and % 0xff)) root))
        sealed (shared/seal ab (utf8 "x"))]
    (is (= 32 (alength ^bytes root)))
    (doseq [out [(pr-str ab) (pr-str sealed) (cedn/canonical-str sealed) (pr-str (shared/mac ab (utf8 "m")))]]
      (is (not (str/includes? out hex))))))

(deftest destroyed-shared-keys-stop-working
  (let [{:keys [ab ba]} (pair)
        sealed (shared/seal ab (utf8 "x"))]
    (vault/destroy! ba)
    (is (false? (:valid? (shared/open ba sealed))))
    (is (false? (shared/verify-mac? ba (utf8 "m") (shared/mac ab (utf8 "m")))))
    (is (= :signet.vault/destroyed-key
           (try (shared/seal ba (utf8 "y")) :no-throw
                (catch clojure.lang.ExceptionInfo e (:type (ex-data e))))))))
