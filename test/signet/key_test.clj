(ns signet.key-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.encoding :as enc]))

;; Clear the global key store between tests
(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; === Predicate tests ===

(deftest predicate-test
  (testing "signing predicates"
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)
          priv (key/signing-private-key kp)]
      (is (key/signing-keypair? kp))
      (is (not (key/encryption-keypair? kp)))
      (is (key/signing-public-key? pub))
      (is (not (key/encryption-public-key? pub)))
      (is (key/signing-private-key? priv))
      (is (not (key/encryption-private-key? priv)))))

  (testing "encryption predicates"
    (let [kp (key/encryption-keypair)
          pub (key/encryption-public-key kp)
          priv (key/encryption-private-key kp)]
      (is (key/encryption-keypair? kp))
      (is (not (key/signing-keypair? kp)))
      (is (key/encryption-public-key? pub))
      (is (not (key/signing-public-key? pub)))
      (is (key/encryption-private-key? priv))
      (is (not (key/signing-private-key? priv))))))

;; === Ed25519 signing keypair tests ===

(deftest signing-keypair-generate-test
  (testing "generates a valid Ed25519 keypair"
    (let [kp (key/signing-keypair)]
      (is (key/signing-keypair? kp))
      (is (= :Ed25519 (:crv kp)))
      (is (= 32 (count (:x kp))))
      (is (= 32 (count (:d kp))))
      (is (instance? signet.key.Ed25519KeyPair kp))))

  (testing "generates unique keypairs"
    (let [kp1 (key/signing-keypair)
          kp2 (key/signing-keypair)]
      (is (not (java.util.Arrays/equals ^bytes (:x kp1) ^bytes (:x kp2)))))))

(deftest signing-keypair-from-bytes-test
  (testing "adopts raw key bytes"
    (let [kp (key/signing-keypair)
          kp2 (key/signing-keypair (:x kp) (:d kp))]
      (is (key/signing-keypair? kp2))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x kp2)))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d kp2))))))

(deftest signing-keypair-from-map-test
  (testing "reconstructs keypair from plain map"
    (let [kp (key/signing-keypair)
          reconstructed (key/signing-keypair {:type :signet/ed25519-keypair
                                              :crv :Ed25519
                                              :x (:x kp)
                                              :d (:d kp)})]
      (is (instance? signet.key.Ed25519KeyPair reconstructed))
      (is (key/signing-keypair? reconstructed))))

  (testing "from-map is idempotent on records"
    (let [kp (key/signing-keypair)]
      (is (instance? signet.key.Ed25519KeyPair (key/signing-keypair kp)))))

  (testing "derives keypair from private key only"
    (let [kp (key/signing-keypair)
          derived (key/signing-keypair {:type :signet/ed25519-private-key
                                        :crv :Ed25519
                                        :d (:d kp)})]
      (is (key/signing-keypair? derived))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x derived)))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d derived))))))

;; === X25519 encryption keypair tests ===

(deftest encryption-keypair-generate-test
  (testing "generates a valid X25519 keypair"
    (let [kp (key/encryption-keypair)]
      (is (key/encryption-keypair? kp))
      (is (= :X25519 (:crv kp)))
      (is (= 32 (count (:x kp))))
      (is (= 32 (count (:d kp))))
      (is (instance? signet.key.X25519KeyPair kp))))

  (testing "generates unique keypairs"
    (let [kp1 (key/encryption-keypair)
          kp2 (key/encryption-keypair)]
      (is (not (java.util.Arrays/equals ^bytes (:x kp1) ^bytes (:x kp2)))))))

(deftest encryption-keypair-from-bytes-test
  (testing "adopts raw key bytes"
    (let [kp (key/encryption-keypair)
          kp2 (key/encryption-keypair (:x kp) (:d kp))]
      (is (key/encryption-keypair? kp2))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x kp2)))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d kp2))))))

(deftest encryption-keypair-from-map-test
  (testing "reconstructs X25519 keypair from plain map"
    (let [kp (key/encryption-keypair)
          reconstructed (key/encryption-keypair {:type :signet/x25519-keypair
                                                 :crv :X25519
                                                 :x (:x kp)
                                                 :d (:d kp)})]
      (is (instance? signet.key.X25519KeyPair reconstructed))
      (is (key/encryption-keypair? reconstructed))))

  (testing "derives keypair from private key only"
    (let [kp (key/encryption-keypair)
          derived (key/encryption-keypair {:type :signet/x25519-private-key
                                           :crv :X25519
                                           :d (:d kp)})]
      (is (key/encryption-keypair? derived))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x derived)))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d derived))))))

;; === signing-public-key / signing-private-key tests ===

(deftest signing-public-key-test
  (testing "extracts from keypair"
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)]
      (is (instance? signet.key.Ed25519PublicKey pub))
      (is (key/signing-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub)))))

  (testing "idempotent on public key"
    (let [pub (key/signing-public-key (key/signing-keypair))]
      (is (identical? pub (key/signing-public-key pub)))))

  (testing "derives from private key"
    (let [kp (key/signing-keypair)
          priv (key/signing-private-key kp)
          pub (key/signing-public-key priv)]
      (is (key/signing-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub))))))

(deftest signing-private-key-test
  (testing "extracts from keypair"
    (let [kp (key/signing-keypair)
          priv (key/signing-private-key kp)]
      (is (instance? signet.key.Ed25519PrivateKey priv))
      (is (key/signing-private-key? priv))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d priv)))))

  (testing "idempotent on private key"
    (let [priv (key/signing-private-key (key/signing-keypair))]
      (is (identical? priv (key/signing-private-key priv))))))

;; === encryption-public-key / encryption-private-key tests ===

(deftest encryption-public-key-test
  (testing "extracts from keypair"
    (let [kp (key/encryption-keypair)
          pub (key/encryption-public-key kp)]
      (is (instance? signet.key.X25519PublicKey pub))
      (is (key/encryption-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub)))))

  (testing "idempotent on public key"
    (let [pub (key/encryption-public-key (key/encryption-keypair))]
      (is (identical? pub (key/encryption-public-key pub)))))

  (testing "derives from private key"
    (let [kp (key/encryption-keypair)
          priv (key/encryption-private-key kp)
          pub (key/encryption-public-key priv)]
      (is (key/encryption-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub))))))

(deftest encryption-private-key-test
  (testing "extracts from keypair"
    (let [kp (key/encryption-keypair)
          priv (key/encryption-private-key kp)]
      (is (instance? signet.key.X25519PrivateKey priv))
      (is (key/encryption-private-key? priv))
      (is (java.util.Arrays/equals ^bytes (:d kp) ^bytes (:d priv)))))

  (testing "idempotent on private key"
    (let [priv (key/encryption-private-key (key/encryption-keypair))]
      (is (identical? priv (key/encryption-private-key priv))))))

;; === public-key / private-key convenience tests ===

(deftest public-key-test
  (testing "delegates to signing-public-key for Ed25519"
    (let [kp (key/signing-keypair)
          pub (key/public-key kp)]
      (is (key/signing-public-key? pub))))

  (testing "delegates to encryption-public-key for X25519"
    (let [kp (key/encryption-keypair)
          pub (key/public-key kp)]
      (is (key/encryption-public-key? pub))))

  (testing "works on private keys (derives public)"
    (let [kp (key/signing-keypair)
          priv (key/private-key kp)
          pub (key/public-key priv)]
      (is (key/signing-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub))))))

(deftest private-key-test
  (testing "delegates to signing-private-key for Ed25519"
    (let [kp (key/signing-keypair)
          priv (key/private-key kp)]
      (is (key/signing-private-key? priv))))

  (testing "delegates to encryption-private-key for X25519"
    (let [kp (key/encryption-keypair)
          priv (key/private-key kp)]
      (is (key/encryption-private-key? priv)))))

;; === kid tests ===

(deftest kid-test
  (testing "kid returns a URN with embedded public key"
    (let [kp (key/signing-keypair)
          id (key/kid kp)]
      (is (string? id))
      (is (.startsWith ^String id "urn:signet:pk:ed25519:"))
      ;; Round-trip: parse kid back to public key
      (let [pub (key/kid->public-key id)]
        (is (key/signing-public-key? pub))
        (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub))))))

  (testing "kid works for X25519 keys"
    (let [kp (key/encryption-keypair)
          id (key/kid kp)]
      (is (.startsWith ^String id "urn:signet:pk:x25519:"))))

  (testing "kid consistent across key forms"
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)
          priv (key/signing-private-key kp)]
      (is (= (key/kid kp) (key/kid pub)))
      (is (= (key/kid kp) (key/kid priv)))))

  (testing "kid->public-key round-trips correctly"
    (let [kp (key/encryption-keypair)
          id (key/kid kp)
          pub (key/kid->public-key id)]
      (is (key/encryption-public-key? pub))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x pub)))))

  (testing "lookup auto-parses kid URN when key not in store"
    (let [kp (key/signing-keypair)
          id (key/kid kp)]
      (key/clear-key-store!)
      ;; Key was cleared but URN is self-describing
      (let [found (key/lookup id)]
        (is (some? found))
        (is (key/signing-public-key? found))
        (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x found)))))))

;; === Ed25519 → X25519 cross-curve conversion tests ===

(deftest ed25519->x25519-keypair-test
  (testing "converts Ed25519 keypair to X25519 keypair"
    (let [ed-kp (key/signing-keypair)
          x-kp (key/encryption-keypair ed-kp)]
      (is (key/encryption-keypair? x-kp))
      (is (= 32 (count (:x x-kp))))
      (is (= 32 (count (:d x-kp))))))

  (testing "conversion is deterministic"
    (let [ed-kp (key/signing-keypair)
          x-kp1 (key/encryption-keypair ed-kp)
          x-kp2 (key/encryption-keypair ed-kp)]
      (is (java.util.Arrays/equals ^bytes (:x x-kp1) ^bytes (:x x-kp2)))
      (is (java.util.Arrays/equals ^bytes (:d x-kp1) ^bytes (:d x-kp2)))))

  (testing "different Ed25519 keys produce different X25519 keys"
    (let [x-kp1 (key/encryption-keypair (key/signing-keypair))
          x-kp2 (key/encryption-keypair (key/signing-keypair))]
      (is (not (java.util.Arrays/equals ^bytes (:x x-kp1) ^bytes (:x x-kp2)))))))

(deftest ed25519->x25519-public-key-test
  (testing "converts Ed25519 public key to X25519 public key"
    (let [ed-pub (key/signing-public-key (key/signing-keypair))
          x-pub (key/encryption-public-key ed-pub)]
      (is (key/encryption-public-key? x-pub))
      (is (= 32 (count (:x x-pub))))))

  (testing "public-only matches full keypair conversion"
    (let [ed-kp (key/signing-keypair)
          x-kp (key/encryption-keypair ed-kp)
          x-pub (key/encryption-public-key (key/signing-public-key ed-kp))]
      (is (java.util.Arrays/equals ^bytes (:x x-kp) ^bytes (:x x-pub))))))

(deftest ed25519->x25519-private-key-test
  (testing "converts Ed25519 private key to X25519 private key"
    (let [ed-priv (key/signing-private-key (key/signing-keypair))
          x-priv (key/encryption-private-key ed-priv)]
      (is (key/encryption-private-key? x-priv))
      (is (= 32 (count (:d x-priv))))))

  (testing "private-only matches full keypair conversion"
    (let [ed-kp (key/signing-keypair)
          x-kp (key/encryption-keypair ed-kp)
          x-priv (key/encryption-private-key (key/signing-private-key ed-kp))]
      (is (java.util.Arrays/equals ^bytes (:d x-kp) ^bytes (:d x-priv))))))

;; === Round-trip tests ===

(deftest round-trip-test
  (testing "keypair -> private-key -> signing-keypair recovers full keypair"
    (let [kp (key/signing-keypair)
          priv (key/signing-private-key kp)
          recovered (key/signing-keypair {:type (:type priv) :crv (:crv priv) :d (:d priv)})]
      (is (key/signing-keypair? recovered))
      (is (java.util.Arrays/equals ^bytes (:x kp) ^bytes (:x recovered))))))

;; === Shared key (DH) tests ===

(deftest raw-shared-secret-x25519-test
  (testing "X25519 DH produces a shared key"
    (let [alice (key/encryption-keypair)
          bob (key/encryption-keypair)
          sk (key/raw-shared-secret alice bob)]
      (is (key/raw-shared-secret? sk))
      (is (= :signet/x25519-shared-secret (:type sk)))
      (is (= :X25519 (:crv sk)))
      (is (= 32 (count (:k sk))))
      (is (string? (:kid-a sk)))
      (is (string? (:kid-b sk)))))

  (testing "DH is symmetric — same shared secret regardless of who initiates"
    (let [alice (key/encryption-keypair)
          bob (key/encryption-keypair)
          sk-ab (key/raw-shared-secret alice bob)
          sk-ba (key/raw-shared-secret bob alice)]
      (is (java.util.Arrays/equals ^bytes (:k sk-ab) ^bytes (:k sk-ba)))))

  (testing "different pairs produce different shared secrets"
    (let [alice (key/encryption-keypair)
          bob (key/encryption-keypair)
          carol (key/encryption-keypair)]
      (is (not (java.util.Arrays/equals
                ^bytes (:k (key/raw-shared-secret alice bob))
                ^bytes (:k (key/raw-shared-secret alice carol)))))))

  (testing "works with keypair + public key"
    (let [alice (key/encryption-keypair)
          bob-pub (key/encryption-public-key (key/encryption-keypair))
          sk (key/raw-shared-secret alice bob-pub)]
      (is (key/raw-shared-secret? sk))))

  (testing "works with private key + public key"
    (let [alice (key/encryption-keypair)
          bob (key/encryption-keypair)
          alice-priv (key/encryption-private-key alice)
          bob-pub (key/encryption-public-key bob)
          sk1 (key/raw-shared-secret alice bob)
          sk2 (key/raw-shared-secret alice-priv bob-pub)]
      (is (java.util.Arrays/equals ^bytes (:k sk1) ^bytes (:k sk2))))))

(deftest raw-shared-secret-ed25519-test
  (testing "Ed25519 keys auto-convert for DH"
    (let [alice (key/signing-keypair)
          bob (key/signing-keypair)
          sk (key/raw-shared-secret alice bob)]
      (is (key/raw-shared-secret? sk))
      (is (= 32 (count (:k sk))))))

  (testing "Ed25519 DH is symmetric"
    (let [alice (key/signing-keypair)
          bob (key/signing-keypair)
          sk-ab (key/raw-shared-secret alice bob)
          sk-ba (key/raw-shared-secret bob alice)]
      (is (java.util.Arrays/equals ^bytes (:k sk-ab) ^bytes (:k sk-ba)))))

  (testing "Ed25519 DH matches explicit X25519 conversion"
    (let [alice-ed (key/signing-keypair)
          bob-ed (key/signing-keypair)
          alice-x (key/encryption-keypair alice-ed)
          bob-x (key/encryption-keypair bob-ed)
          sk-ed (key/raw-shared-secret alice-ed bob-ed)
          sk-x (key/raw-shared-secret alice-x bob-x)]
      (is (java.util.Arrays/equals ^bytes (:k sk-ed) ^bytes (:k sk-x))))))

(deftest raw-shared-secret-mixed-test
  (testing "Ed25519 keypair + X25519 public key"
    (let [alice-ed (key/signing-keypair)
          bob-x (key/encryption-keypair)
          sk (key/raw-shared-secret alice-ed (key/encryption-public-key bob-x))]
      (is (key/raw-shared-secret? sk))))

  (testing "mixed keys produce same shared secret as fully converted"
    (let [alice-ed (key/signing-keypair)
          bob-x (key/encryption-keypair)
          alice-x (key/encryption-keypair alice-ed)
          sk-mixed (key/raw-shared-secret alice-ed bob-x)
          sk-x (key/raw-shared-secret alice-x bob-x)]
      (is (java.util.Arrays/equals ^bytes (:k sk-mixed) ^bytes (:k sk-x)))))

  (testing "kid-a and kid-b reflect original key identities"
    (let [alice (key/signing-keypair)
          bob (key/encryption-keypair)
          sk (key/raw-shared-secret alice bob)]
      (is (= (key/kid alice) (:kid-a sk)))
      (is (= (key/kid bob) (:kid-b sk))))))

;; === Key store tests ===

(deftest key-store-auto-register-test
  (testing "signing-keypair auto-registers"
    (let [kp (key/signing-keypair)
          found (key/lookup (key/kid kp))]
      (is (some? found))
      (is (key/signing-keypair? found))))

  (testing "encryption-keypair auto-registers"
    (let [kp (key/encryption-keypair)
          found (key/lookup (key/kid kp))]
      (is (some? found))
      (is (key/encryption-keypair? found))))

  (testing "signing-keypair from map auto-registers"
    (let [kp (key/signing-keypair)
          _ (key/clear-key-store!)
          kp2 (key/signing-keypair {:type :signet/ed25519-keypair
                                     :crv :Ed25519
                                     :x (:x kp) :d (:d kp)})]
      (is (some? (key/lookup (key/kid kp2))))))

  (testing "public-key extraction auto-registers"
    (let [kp (key/signing-keypair)
          _ (key/clear-key-store!)
          pub (key/signing-public-key kp)]
      (is (some? (key/lookup (key/kid pub))))))

  (testing "raw-shared-secret auto-registers both parties"
    (let [alice (key/signing-keypair)
          bob (key/signing-keypair)
          _ (key/clear-key-store!)
          _ (key/raw-shared-secret alice bob)]
      (is (some? (key/lookup (key/kid alice))))
      (is (some? (key/lookup (key/kid bob)))))))

(deftest key-store-most-info-wins-test
  (testing "keypair is not overwritten by public key"
    (let [kp (key/signing-keypair)
          kid-str (key/kid kp)
          _ (key/register! (key/signing-public-key kp))
          found (key/lookup kid-str)]
      (is (key/signing-keypair? found))
      (is (some? (:d found)))))

  (testing "public key is upgraded to keypair"
    (key/clear-key-store!)
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)
          kid-str (key/kid kp)]
      (key/clear-key-store!)
      (key/register! pub)
      (is (key/signing-public-key? (key/lookup kid-str)))
      (key/register! kp)
      (is (key/signing-keypair? (key/lookup kid-str)))))

  (testing "private key upgrades public key but not keypair"
    (key/clear-key-store!)
    (let [kp (key/signing-keypair)
          pub (key/signing-public-key kp)
          priv (key/signing-private-key kp)
          kid-str (key/kid kp)]
      (key/clear-key-store!)
      (key/register! pub)
      (is (key/signing-public-key? (key/lookup kid-str)))
      (key/register! priv)
      (is (key/signing-private-key? (key/lookup kid-str)))
      (key/register! kp)
      (is (key/signing-keypair? (key/lookup kid-str))))))

(deftest key-store-operations-test
  (testing "registered-keys returns all keys"
    (let [kp1 (key/signing-keypair)
          kp2 (key/encryption-keypair)]
      (is (= 2 (count (key/registered-keys))))))

  (testing "unregister! removes a key from store"
    (let [kp (key/signing-keypair)
          kid-str (key/kid kp)]
      (is (some? (key/lookup kid-str)))
      (is (key/signing-keypair? (key/lookup kid-str)))
      (key/unregister! kid-str)
      ;; URN is self-describing so lookup still works (re-parses to public key)
      ;; but the keypair is gone — only public key remains
      (is (key/signing-public-key? (key/lookup kid-str)))))

  (testing "clear-key-store! empties the store"
    (key/signing-keypair)
    (key/encryption-keypair)
    (is (pos? (count (key/registered-keys))))
    (key/clear-key-store!)
    (is (zero? (count (key/registered-keys)))))

  (testing "register! is idempotent"
    (let [kp (key/signing-keypair)]
      (key/register! kp)
      (key/register! kp)
      (key/register! kp)
      (is (= 1 (count (key/registered-keys)))))))

;; === Default key tests ===

(deftest default-signing-keypair-test
  (testing "no default initially"
    (is (nil? (key/default-signing-keypair))))

  (testing "first signing keypair becomes default"
    (let [kp (key/signing-keypair)]
      (is (some? (key/default-signing-keypair)))
      (is (java.util.Arrays/equals ^bytes (:x kp)
                                   ^bytes (:x (key/default-signing-keypair))))))

  (testing "second keypair does not override (first-one-wins)"
    (let [first-kp (key/default-signing-keypair)
          _kp2 (key/signing-keypair)]
      (is (java.util.Arrays/equals ^bytes (:x first-kp)
                                   ^bytes (:x (key/default-signing-keypair))))))

  (testing "explicit set overrides"
    (let [kp3 (key/signing-keypair)]
      (key/set-default-signing-keypair! kp3)
      (is (java.util.Arrays/equals ^bytes (:x kp3)
                                   ^bytes (:x (key/default-signing-keypair))))))

  (testing "clear-defaults! resets"
    (key/clear-defaults!)
    (is (nil? (key/default-signing-keypair))))

  (testing "clear-key-store! also clears defaults"
    (key/signing-keypair)
    (is (some? (key/default-signing-keypair)))
    (key/clear-key-store!)
    (is (nil? (key/default-signing-keypair)))))

(deftest default-encryption-keypair-test
  (testing "first encryption keypair becomes default"
    (let [kp (key/encryption-keypair)]
      (is (some? (key/default-encryption-keypair)))
      (is (java.util.Arrays/equals ^bytes (:x kp)
                                   ^bytes (:x (key/default-encryption-keypair))))))

  (testing "second does not override"
    (let [first-kp (key/default-encryption-keypair)
          _kp2 (key/encryption-keypair)]
      (is (java.util.Arrays/equals ^bytes (:x first-kp)
                                   ^bytes (:x (key/default-encryption-keypair))))))

  (testing "explicit set overrides"
    (let [kp3 (key/encryption-keypair)]
      (key/set-default-encryption-keypair! kp3)
      (is (java.util.Arrays/equals ^bytes (:x kp3)
                                   ^bytes (:x (key/default-encryption-keypair)))))))

(deftest default-keys-independent-test
  (testing "signing and encryption defaults are independent"
    (let [sign-kp (key/signing-keypair)
          enc-kp (key/encryption-keypair)]
      (is (key/signing-keypair? (key/default-signing-keypair)))
      (is (key/encryption-keypair? (key/default-encryption-keypair)))
      (is (not= (:type (key/default-signing-keypair))
                (:type (key/default-encryption-keypair))))))

  (testing "ed25519->x25519 conversion sets encryption default"
    (key/clear-key-store!)
    (let [ed-kp (key/signing-keypair)
          x-kp (key/encryption-keypair ed-kp)]
      (is (some? (key/default-encryption-keypair)))
      (is (java.util.Arrays/equals ^bytes (:x x-kp)
                                   ^bytes (:x (key/default-encryption-keypair)))))))

;; ============================================================
;; kid <-> hex conversions
;; ============================================================

(deftest kid->hex-round-trip-test
  (testing "kid -> hex -> kid gives back the same URN"
    (let [kp (key/signing-keypair)
          kid-urn (key/kid kp)
          hex (key/kid->hex kid-urn)]
      (is (= 64 (count hex)) "Ed25519 pub key = 32 bytes = 64 hex chars")
      (is (re-matches #"[0-9a-f]+" hex) "lowercase hex only")
      (is (= kid-urn (key/hex->kid hex))))))

(deftest kid->hex-accepts-record-or-urn-test
  (let [kp (key/signing-keypair)]
    (is (= (key/kid->hex kp)
           (key/kid->hex (key/kid kp)))
        "kid->hex should accept either a key record or a URN string")))

(deftest kid->hex-matches-raw-bytes-test
  (let [kp (key/signing-keypair)]
    (is (= (key/kid->hex kp)
           (enc/bytes->hex (:x kp))))))

(deftest hex->kid-explicit-curve-test
  (testing "x25519 keys require explicit curve"
    (let [kp (key/encryption-keypair)
          hex (enc/bytes->hex (:x kp))
          urn (key/hex->kid hex :X25519)]
      (is (clojure.string/starts-with? urn "urn:signet:pk:x25519:"))
      (is (= (key/kid kp) urn)))))

(deftest hex->bytes-accepts-0x-prefix-test
  (let [raw (byte-array [0x00 0x01 0xAB 0xCD])
        hex-plain  (enc/bytes->hex raw)
        hex-prefix (str "0x" hex-plain)]
    (is (java.util.Arrays/equals raw (enc/hex->bytes hex-plain)))
    (is (java.util.Arrays/equals raw (enc/hex->bytes hex-prefix)))))

(deftest hex->bytes-rejects-odd-length-test
  (is (thrown? clojure.lang.ExceptionInfo
               (enc/hex->bytes "abc"))))
