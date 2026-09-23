(ns signet.encryption-test
  "box v2 (docs/06-box-v2-design.md): self-describing, directional,
   nonce-safe authenticated encryption between signet identities."
  (:require [cedn.core :as cedn]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encryption :as enc]
            [signet.impl :as impl]
            [signet.key :as key]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

(defn- utf8 [^String s] (.getBytes s "UTF-8"))
(defn- text [^bytes bs] (String. bs "UTF-8"))
(defn- plaintext [r] (some-> (:plaintext r) text))

(defn- alice+bob [] [(key/encryption-keypair) (key/encryption-keypair)])

;; ---------------------------------------------------------------------------
;; Round trips and format
;; ---------------------------------------------------------------------------

(deftest round-trip-x25519-and-ed25519
  (doseq [[label mk] [["x25519" key/encryption-keypair] ["ed25519" key/signing-keypair]]]
    (let [alice (mk) bob (mk)
          boxed (enc/box alice (key/public-key bob) (utf8 "hello bob"))
          r     (enc/unbox bob boxed)]
      (is (true? (:valid? r)) label)
      (is (= "hello bob" (plaintext r)) label)
      (is (= (key/kid alice) (:from r)) (str label ": sender reported from the :from slot")))))

(deftest wire-format
  (let [[alice bob] (alice+bob)
        boxed (enc/box alice bob (utf8 "x"))]
    (is (= :signet/box (:type boxed)))
    (is (= 2 (:v boxed)))
    (is (= 24 (alength ^bytes (:nonce boxed))) "24-byte random nonce, always present")
    (is (= (key/kid alice) (:from boxed)) "sender kid slot on by default")
    (is (= (key/kid bob) (:to boxed)) "recipient kid slot on by default")
    (is (= 17 (alength ^bytes (:ct boxed))) "ciphertext = plaintext + 16-byte tag")
    (testing "the box is plain EDN: it round-trips through cedn text"
      (let [back (edn/read-string {:readers cedn/readers} (cedn/canonical-str boxed))]
        (is (= "x" (plaintext (enc/unbox bob back))))))))

(deftest empty-and-large-plaintexts
  (let [[alice bob] (alice+bob)
        big (byte-array 100000 (byte 7))]
    (is (= "" (plaintext (enc/unbox bob (enc/box alice bob (byte-array 0))))))
    (is (java.util.Arrays/equals big ^bytes (:plaintext (enc/unbox bob (enc/box alice bob big)))))))

;; ---------------------------------------------------------------------------
;; Spec conformance (and, run under both backends, byte parity)
;; ---------------------------------------------------------------------------

(deftest conforms-to-the-design-note
  (let [[alice bob] (alice+bob)
        boxed  (enc/box alice bob (utf8 "spec") {:aad {:ctx 1}})
        header (dissoc boxed :ct)
        info   (byte-array (concat (utf8 "signet/box/v2") (:x alice) (:x bob)))
        shared (impl/x25519-dh (:d bob) (:x alice))
        k      (impl/hkdf-sha-256 shared (:nonce boxed) info 32)
        pt     (impl/chacha20-poly1305-decrypt k (byte-array 12) (:ct boxed)
                                               (cedn/canonical-bytes header))]
    (is (= "spec" (text pt))
        "k = HKDF(X25519, salt=nonce, info=v2 tag ‖ sender_x25519 ‖ recipient_x25519); AEAD nonce 0^96; AAD = cedn(header)")))

;; ---------------------------------------------------------------------------
;; Directional keys: reflection is impossible (finding 7)
;; ---------------------------------------------------------------------------

(deftest reflection-fails
  (let [[alice bob] (alice+bob)
        boxed (enc/box alice bob (utf8 "transfer 100 to bob"))]
    (testing "Alice cannot be made to read her own A→B box as B→A"
      (is (false? (:valid? (enc/unbox alice (assoc boxed :from (key/kid bob) :to (key/kid alice)))))
          "with the slots swapped")
      (is (false? (:valid? (enc/unbox alice (dissoc boxed :from :to) {:from (key/kid bob)})))
          "with the slots stripped and Bob named as sender"))
    (testing "a slot-less box: the header gives nothing away, so only the
              directional key stops the reflection"
      (let [quiet (enc/box alice bob (utf8 "transfer 100 to bob") {:from? false :to? false})]
        (is (true? (:valid? (enc/unbox bob quiet {:from (key/kid alice)}))) "Bob reads it")
        (is (false? (:valid? (enc/unbox alice quiet {:from (key/kid bob)})))
            "Alice cannot read her own box as if Bob had sent it")))))

;; ---------------------------------------------------------------------------
;; Slots: optional, hints only, bound even when omitted
;; ---------------------------------------------------------------------------

(deftest omitted-slots
  (let [[alice bob] (alice+bob)
        boxed (enc/box alice bob (utf8 "quiet") {:from? false :to? false})]
    (is (not (contains? boxed :from)))
    (is (not (contains? boxed :to)))
    (is (false? (:valid? (enc/unbox bob boxed))) "no sender slot and no expectation: cannot decrypt")
    (is (= "quiet" (plaintext (enc/unbox bob boxed {:from (key/kid alice)})))
        "the caller supplies the sender")
    (is (false? (:valid? (enc/unbox bob boxed {:from (key/kid (key/encryption-keypair))})))
        "an omitted slot is still bound: the wrong sender fails")))

(deftest recipient-chosen-by-to-slot
  (let [[alice bob] (alice+bob)
        carol (key/encryption-keypair)
        boxed (enc/box alice bob (utf8 "for bob"))]
    (is (= "for bob" (plaintext (enc/unbox [carol bob] boxed))) ":to picks Bob among candidates")
    (is (= "for bob" (plaintext (enc/unbox [carol bob] (enc/box alice bob (utf8 "for bob") {:to? false}))))
        "a box sent without :to: every candidate is tried")
    (is (false? (:valid? (enc/unbox carol boxed))) "the wrong recipient cannot decrypt")))

(deftest kid-forms-are-interchangeable
  (let [alice (key/signing-keypair) bob (key/signing-keypair)
        via-ed (enc/box alice (key/public-key bob) (utf8 "ed"))
        via-x  (enc/box alice (key/encryption-public-key bob) (utf8 "x"))]
    (is (.startsWith ^String (:to via-ed) "urn:signet:pk:ed25519:"))
    (is (.startsWith ^String (:to via-x) "urn:signet:pk:x25519:"))
    (is (= "ed" (plaintext (enc/unbox bob via-ed))))
    (is (= "x" (plaintext (enc/unbox bob via-x))) "same identity, either kid form, same key")
    (is (false? (:valid? (enc/unbox bob (assoc via-ed :to (key/kid (key/encryption-public-key bob))))))
        "but the slot's form is authenticated: changing it in transit fails")))

;; ---------------------------------------------------------------------------
;; Trust: valid vs verified
;; ---------------------------------------------------------------------------

(deftest valid-vs-verified
  (let [[alice bob] (alice+bob)
        mallory (key/encryption-keypair)
        from-mallory (enc/box mallory bob (utf8 "trust me"))]
    (is (true? (:valid? (enc/unbox bob from-mallory))) "a stranger's box is valid...")
    (is (nil? (:verified? (enc/unbox bob from-mallory))) "...but not verified without an expectation")
    (let [r (enc/unbox bob from-mallory {:from (key/kid alice)})]
      (is (false? (:valid? r)))
      (is (false? (:verified? r))))
    (is (true? (:verified? (enc/unbox bob (enc/box alice bob (utf8 "hi")) {:from #{(key/kid alice)}})))
        ":from may be a set")))

;; ---------------------------------------------------------------------------
;; :aad slot
;; ---------------------------------------------------------------------------

(deftest aad-slot
  (let [[alice bob] (alice+bob)
        ctx   {:request-id #uuid "0195a4c8-1234-7abc-8bcd-0123456789ab" :step [1 2]}
        boxed (enc/box alice bob (utf8 "ctx") {:aad ctx})]
    (is (= ctx (:aad boxed)) "any EDN value, carried in the header")
    (is (= ctx (:aad (enc/unbox bob boxed))) "returned to the receiver")
    (is (true? (:valid? (enc/unbox bob boxed {:aad ctx}))))
    (is (false? (:valid? (enc/unbox bob boxed {:aad {:request-id :other}}))) "mismatch is invalid")
    (is (false? (:valid? (enc/unbox bob (enc/box alice bob (utf8 "none")) {:aad ctx})))
        "an expected :aad that is missing is invalid")))

;; ---------------------------------------------------------------------------
;; Tampering, robustness, hygiene
;; ---------------------------------------------------------------------------

(deftest tampering-any-field-fails
  (let [[alice bob] (alice+bob)
        boxed (enc/box alice bob (utf8 "original") {:aad {:n 1}})
        flip  (fn [^bytes bs] (let [c (aclone bs)] (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c))]
    (doseq [[label t] [["ct" (update boxed :ct flip)]
                       ["nonce" (update boxed :nonce flip)]
                       ["v" (assoc boxed :v 3)]
                       ["aad changed" (assoc boxed :aad {:n 2})]
                       ["aad removed" (dissoc boxed :aad)]
                       ["to removed" (dissoc boxed :to)]
                       ["extra slot" (assoc boxed :x 1)]]]
      (is (false? (:valid? (enc/unbox bob t))) label))))

(deftest unbox-never-throws
  (let [[alice bob] (alice+bob)
        good (enc/box alice bob (utf8 "ok"))]
    (doseq [[label recipient boxed]
            [["nil box" bob nil]
             ["v1 raw bytes" bob (byte-array 40)]
             ["not a box" bob {:a 1}]
             ["short nonce" bob (assoc good :nonce (byte-array 12))]
             ["short ct" bob (assoc good :ct (byte-array 5))]
             ["ct not bytes" bob (assoc good :ct "x")]
             ["garbage from" bob (assoc good :from "urn:signet:pk:x25519:!!!")]
             ["from not a string" bob (assoc good :from 42)]
             ["no recipient keys" [] good]
             ["nil recipient" nil good]]]
      (let [r (try (enc/unbox recipient boxed)
                   (catch Throwable t {:threw (str (class t) " " (ex-message t))}))]
        (is (not (contains? r :threw)) (str label ": " (:threw r)))
        (is (false? (:valid? r)) label)))))

(deftest box-and-unbox-register-nothing
  (let [alice  (key/signing-keypair)
        bob    (key/signing-keypair)
        carol  (key/encryption-keypair)
        before (set (map key/kid (key/registered-keys)))]
    (enc/unbox bob (enc/box alice (key/public-key bob) (utf8 "x")))
    (enc/unbox bob (enc/box carol (key/public-key bob) (utf8 "y")) {:from (key/kid carol)})
    (is (= 3 (count before)))
    (is (= before (set (map key/kid (key/registered-keys))))
        "boxing, resolving kid slots and unboxing registered nothing")))

(deftest nonces-never-repeat
  (let [[alice bob] (alice+bob)
        n      20000
        nonces (into #{} (map (fn [_] (vec (:nonce (enc/box alice bob (byte-array 0)))))) (range n))]
    (is (= n (count nonces)))))
