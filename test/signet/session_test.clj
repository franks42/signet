(ns signet.session-test
  "Tests for signet.session: Noise_KK forward-secret sessions.

   Each test sets up two parties (alice as initiator, bob as responder)
   with mutual knowledge of each other's static public keys, drives a
   handshake, and exercises transport messages. Identities are vault
   handles (Ed25519 in most cases, the consumer pattern: long-term Ed25519
   identities with auto-conversion to X25519); one test keeps the
   deprecated key-record inputs working.

   The lifecycle tests at the end check where session secrets live: only
   in the vault, destroyed as soon as no state needs them, and all gone
   after close! or with-conclave."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.key :as key]
            [signet.session :as session]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (vault/reset-default-vault!) (f)))

;; ---- Helpers ----

(defn- bytes= [a b]
  (java.util.Arrays/equals ^bytes a ^bytes b))

(defn- utf8 ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type
  "The ex-data :type f throws, :no-throw, or [:not-ex-info class]. Session
   errors are typed and the same on every backend."
  [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (str (class e))]))))

(defn- identity! [] (vault/generate-signing-key!))

(defn- pub [h] (vault/public-key h))

(defn- run-handshake
  "Drive the two-message KK handshake to completion. Returns the
   handshake-final states for each side plus the application payloads
   each side received from its peer."
  [alice-init bob-resp init-payload resp-payload]
  (let [[alice-1 msg1]    (session/write-message! alice-init init-payload)
        [bob-1   pt-init] (session/read-message!  bob-resp msg1)
        [bob-2   msg2]    (session/write-message! bob-1 resp-payload)
        [alice-2 pt-resp] (session/read-message!  alice-1 msg2)]
    {:alice    alice-2
     :bob      bob-2
     :init-pt  pt-init
     :resp-pt  pt-resp
     :msg1     msg1
     :msg2     msg2}))

(defn- pair
  "Fresh initiator and responder states between two new identities."
  ([] (pair nil))
  ([opts]
   (let [alice (identity!) bob (identity!)]
     [(session/initiator alice (pub bob) opts) (session/responder bob (pub alice) opts)])))

(defn- established-pair []
  (let [[ai br] (pair)
        {:keys [alice bob]} (run-handshake ai br (byte-array 0) (byte-array 0))]
    [alice bob]))

;; ---- Handshake roundtrip ----

(deftest handshake-roundtrip-ed25519
  (testing "two Ed25519 identities complete a KK handshake"
    (let [[ai br] (pair)
          init-payload (utf8 "init payload")
          resp-payload (utf8 "resp payload")
          {:keys [alice bob init-pt resp-pt]} (run-handshake ai br init-payload resp-payload)]
      (is (session/established? alice))
      (is (session/established? bob))
      (is (bytes= init-payload init-pt))
      (is (bytes= resp-payload resp-pt)))))

(deftest handshake-roundtrip-x25519
  (testing "two native X25519 identities complete a KK handshake"
    (let [alice (vault/generate-encryption-key!)
          bob   (vault/generate-encryption-key!)
          ai    (session/initiator alice (pub bob))
          br    (session/responder bob   (pub alice))
          {:keys [alice bob]} (run-handshake ai br (utf8 "a") (utf8 "b"))]
      (is (session/established? alice))
      (is (session/established? bob)))))

(deftest peers-by-kid
  (testing "the remote static key may be given as its kid"
    (let [alice (identity!) bob (identity!)
          ai (session/initiator alice (:kid bob))
          br (session/responder bob (:kid alice))
          {:keys [alice bob]} (run-handshake ai br (utf8 "x") (utf8 "y"))]
      (is (session/established? alice))
      (is (session/established? bob))))
  (testing "an unresolvable kid is refused up front"
    (is (= :signet.session/unknown-peer
           (error-type #(session/initiator (identity!) "urn:signet:pk:ed25519:nope"))))))

(deftest deprecated-key-records-still-work
  (testing "key records as static keys (deprecated): same handshake, secrets still in the vault"
    (let [alice (key/signing-keypair)
          bob   (key/signing-keypair)
          ai    (session/initiator alice (key/signing-public-key bob))
          br    (session/responder bob   (key/signing-public-key alice))
          {:keys [alice bob init-pt]} (run-handshake ai br (utf8 "hi") (utf8 "yo"))]
      (is (session/established? alice))
      (is (session/established? bob))
      (is (bytes= (utf8 "hi") init-pt))
      (is (= 4 (vault/session-entry-count)) "two transport keys per side, in :default")
      (session/close! alice)
      (session/close! bob)
      (is (zero? (vault/session-entry-count))))))

(deftest handshake-empty-payloads
  (testing "handshake messages may carry no application data"
    (let [[ai br] (pair)
          {:keys [alice bob init-pt resp-pt]}
          (run-handshake ai br (byte-array 0) (byte-array 0))]
      (is (session/established? alice))
      (is (session/established? bob))
      (is (zero? (alength ^bytes init-pt)))
      (is (zero? (alength ^bytes resp-pt))))))

(deftest handshake-with-prologue
  (testing "matching prologues complete; mismatched ones fail"
    (let [alice (identity!)
          bob   (identity!)
          good  (utf8 "ceremony-id-foo")
          bad   (utf8 "ceremony-id-bar")]
      (testing "matching prologue succeeds"
        (let [ai (session/initiator alice (pub bob) {:prologue good})
              br (session/responder bob   (pub alice) {:prologue good})
              {:keys [alice bob]} (run-handshake ai br (byte-array 0) (byte-array 0))]
          (is (session/established? alice))
          (is (session/established? bob))))
      (testing "mismatched prologue causes message-1 read to fail"
        (let [ai (session/initiator alice (pub bob) {:prologue good})
              br (session/responder bob   (pub alice) {:prologue bad})
              [_ai m1] (session/write-message! ai (byte-array 0))]
          (is (thrown? Exception (session/read-message! br m1))))))))

;; ---- Transport ----

(deftest transport-roundtrip-bidirectional
  (testing "after handshake, both sides can send transport messages"
    (let [[alice bob] (established-pair)
          msg-a    (utf8 "alice → bob 1")
          msg-b    (utf8 "bob → alice 1")
          [_alice' ct1] (session/write-message! alice msg-a)
          [bob'    pt1] (session/read-message!  bob ct1)
          [_bob''  ct2] (session/write-message! bob' msg-b)
          [_       pt2] (session/read-message!  _alice' ct2)]
      (is (bytes= msg-a pt1))
      (is (bytes= msg-b pt2)))))

(deftest transport-multiple-messages
  (testing "nonce counters increment correctly across many transport msgs"
    (let [[alice bob] (established-pair)]
      (loop [alice alice
             bob   bob
             i     0]
        (when (< i 64)
          (let [pt (utf8 (str "msg-" i))
                [alice' ct]  (session/write-message! alice pt)
                [bob'   got] (session/read-message!  bob ct)]
            (is (bytes= pt got))
            (recur alice' bob' (inc i))))))))

;; ---- Failure modes ----

(deftest tampered-handshake-msg1-fails
  (testing "flipping a byte of msg1 causes responder's read to throw"
    (let [[ai br]  (pair)
          [_ai m1] (session/write-message! ai (utf8 "hi"))
          tampered (let [bs (aclone ^bytes m1)]
                     (aset-byte bs 40 (unchecked-byte (bit-xor (aget bs 40) 0xff)))
                     bs)]
      (is (= :signet.session/authentication-failed
             (error-type #(session/read-message! br tampered)))))))

(deftest tampered-transport-fails
  (testing "flipping a byte of a transport ciphertext causes recv to throw"
    (let [[alice bob]  (established-pair)
          [_alice ct]  (session/write-message! alice (utf8 "secret"))
          tampered     (let [bs (aclone ^bytes ct)]
                         (aset-byte bs 0 (unchecked-byte (bit-xor (aget bs 0) 0xff)))
                         bs)]
      (is (= :signet.session/authentication-failed
             (error-type #(session/read-message! bob tampered)))))))

(deftest wrong-remote-static-fails
  (testing "responder using the wrong claimed initiator-static rejects msg1"
    (let [alice (identity!)
          bob   (identity!)
          eve   (identity!) ; wrong identity
          ai    (session/initiator alice (pub bob))
          ;; bob expects eve, not alice. The 'ss' DH on each side will
          ;; produce different outputs, so the AEAD on msg 1's payload
          ;; fails to decrypt.
          br-wrong (session/responder bob (pub eve))
          [_ai m1] (session/write-message! ai (utf8 "hi"))]
      (is (= :signet.session/authentication-failed
             (error-type #(session/read-message! br-wrong m1)))))))

(deftest wrong-message-phase-fails
  (testing "calling write-message! on a state that should read raises"
    (let [[_ br] (pair)]
      ;; Responder must read msg1 first; calling write-message! at pos 0
      ;; (responder's responsibility is to wait) raises.
      (is (= :signet.session/wrong-message-phase
             (error-type #(session/write-message! br (byte-array 0))))))))

(deftest truncated-handshake-message-fails
  (testing "a too-short msg1 raises with a clear reason"
    (let [[_ br] (pair)]
      (is (= :signet.session/handshake-message-too-short
             (error-type #(session/read-message! br (byte-array 10))))))))

(deftest local-static-key-needs-its-private-part
  (let [alice (identity!) bob (identity!)]
    (doseq [[label f] {"a public key record"     #(session/initiator (pub alice) (pub bob))
                       "a public key (responder)" #(session/responder (pub bob) (pub alice))
                       "a destroyed handle"      #(let [h (identity!)] (vault/destroy! h) (session/initiator h (pub bob)))
                       "a handle nobody holds"   #(session/initiator (assoc alice :kid (:kid (key/signing-keypair))) (pub bob))}]
      (is (= :signet.session/no-private-key (error-type f))
          (str label ": refused up front, not deep in the handshake")))))

;; ---- Forward secrecy property ----

(deftest forward-secrecy-via-distinct-ephemerals
  (testing "two sessions between the same parties produce different transport keys"
    (let [alice (identity!)
          bob   (identity!)
          first-ct
          (fn []
            (let [ai (session/initiator alice (pub bob))
                  br (session/responder bob   (pub alice))
                  {alice :alice} (run-handshake ai br (byte-array 0) (byte-array 0))]
              ;; The same plaintext at the same nonce: equal ciphertexts
              ;; would mean equal send keys.
              (vec (second (session/write-message! alice (utf8 "same"))))))]
      (is (not= (first-ct) (first-ct))
          "two sessions with same long-term keys should derive different session keys"))))

;; ---- Lifecycle: where session secrets live (docs/08 phases 3–4) ----

(defn- count-entries [] (vault/session-entry-count))

(deftest secrets-follow-the-live-states
  (let [[i0 r0] (pair)]
    (is (zero? (count-entries)) "initiator/responder put nothing in the vault")
    (let [[i1 m1] (session/write-message! i0 (utf8 "1"))]
      (is (= 3 (count-entries)) "initiator after msg1: ck, k, its ephemeral")
      (let [[r1 _] (session/read-message! r0 m1)]
        (is (= 5 (count-entries)) "responder after msg1: ck, k (no ephemeral yet)")
        (let [[r2 m2] (session/write-message! r1 (utf8 "2"))]
          (is (= 5 (count-entries)) "responder established: 2 transport keys; its ephemeral already gone")
          (let [[i2 _] (session/read-message! i1 m2)]
            (is (= 4 (count-entries)) "both established: 2 transport keys per side")
            (let [[i3 ct] (session/write-message! i2 (utf8 "t"))
                  [r3 _]  (session/read-message! r2 ct)]
              (is (= 4 (count-entries)) "transport messages create no entries")
              (session/close! i3)
              (is (= 2 (count-entries)) "close! destroys only its own session")
              (session/close! r3)
              (is (zero? (count-entries))))))))))

(deftest failed-reads-leave-nothing-behind
  (let [[i0 r0] (pair)
        [i1 m1] (session/write-message! i0 (utf8 "1"))
        before  (count-entries)
        forged  (let [c (aclone ^bytes m1)] (aset-byte c 40 (unchecked-byte (bit-xor (aget c 40) 1))) c)]
    (is (= :signet.session/authentication-failed (error-type #(session/read-message! r0 forged))))
    (is (= before (count-entries)) "the forged read's ck/k were destroyed")
    (let [[r1 _] (session/read-message! r0 m1)]
      (is (session/established? (first (session/read-message! i1 (second (session/write-message! r1 nil)))))
          "the genuine message still completes the handshake"))))

(deftest no-secret-bytes-in-any-state
  (let [[i0 r0] (pair)
        [i1 m1] (session/write-message! i0 (utf8 "1"))
        [r1 _]  (session/read-message! r0 m1)
        [r2 m2] (session/write-message! r1 (utf8 "2"))
        [i2 _]  (session/read-message! i1 m2)
        byte-arrays (fn [st] (->> (tree-seq coll? #(if (map? %) (vals %) (seq %)) st)
                                  (filter bytes?)))
        ;; before msg1 the chaining key is still the public protocol name
        public-bytes (fn [st] (set (map vec (concat [(:h st)] (when (bytes? (:ck st)) [(:ck st)])
                                                    (keep :x [(:local-ephemeral st) (:remote-ephemeral-pub st)
                                                              (:remote-static-pub st)])))))]
    (doseq [[label st] {"i0" i0 "i1" i1 "r1" r1 "r2" r2 "i2" i2}]
      (is (every? (public-bytes st) (map vec (byte-arrays st)))
          (str label ": the only byte arrays are h and public keys"))
      (is (every? #(or (vault/handle? %) (not (instance? signet.session.EphemeralKeyPair %)) (vault/handle? (:handle %)))
                  (tree-seq coll? seq st))))))

(deftest replaced-secrets-are-destroyed
  (let [[i0 r0] (pair)
        [i1 m1] (session/write-message! i0 (utf8 "1"))
        [r1 _]  (session/read-message! r0 m1)
        [r2 m2] (session/write-message! r1 (utf8 "2"))
        [i2 _]  (session/read-message! i1 m2)
        dead?   #(= :signet.vault/destroyed-key
                    (error-type (fn [] (vault/aead-encrypt % (byte-array 12) (byte-array 1) nil))))]
    (is (dead? (:ck i1)) "the handshake chaining key is gone after Split")
    (is (dead? (:k i1)))
    (is (dead? (get-in i1 [:local-ephemeral :handle])) "the ephemeral is gone after Split")
    (is (dead? (:k r1)))
    (is (not (dead? (get-in i2 [:send :k]))))
    (is (not (dead? (get-in r2 [:send :k]))))))

(deftest close!-from-the-first-state
  (let [[i0 r0] (pair)
        [i1 m1] (session/write-message! i0 (utf8 "1"))
        [r1 _]  (session/read-message! r0 m1)
        [r2 m2] (session/write-message! r1 (utf8 "2"))
        [i2 _]  (session/read-message! i1 m2)
        [i3 _]  (session/write-message! i2 (utf8 "t"))]
    (is (nil? (session/close! i0)) "the state bound at the start, long consumed")
    (is (nil? (session/close! r0)))
    (is (zero? (count-entries)) "closes the whole session")
    (is (nil? (session/close! i0)) "closing again is a no-op")
    (doseq [[label f] {"write from the latest state" #(session/write-message! i3 (utf8 "x"))
                       "read from the latest state"  #(session/read-message! r2 (byte-array 16))
                       "write from the first state"  #(session/write-message! i0 (utf8 "x"))}]
      (is (= :signet.session/session-closed (error-type f)) label))))

(deftest with-conclave-closes-on-exit
  (let [alice (identity!) bob (identity!)]
    (testing "normal exit"
      (session/with-conclave [i (session/initiator alice (pub bob))]
        (session/with-conclave [r (session/responder bob (pub alice))]
          (let [{:keys [alice bob]} (run-handshake i r (utf8 "1") (utf8 "2"))
                [_ ct] (session/write-message! alice (utf8 "t"))]
            (is (bytes= (utf8 "t") (second (session/read-message! bob ct))))
            (is (= 4 (count-entries))))))
      (is (zero? (count-entries))))
    (testing "an exception after several messages still closes, and propagates"
      (let [thrown (try
                     (session/with-conclave [i (session/initiator alice (pub bob))]
                       (let [[_ _] (session/write-message! i (utf8 "1"))]
                         (is (= 3 (count-entries)))
                         (throw (ex-info "boom" {:type ::boom}))))
                     (catch clojure.lang.ExceptionInfo e (:type (ex-data e))))]
        (is (= ::boom thrown) "the body's exception, not a close! error")
        (is (zero? (count-entries)))))))

(deftest two-sessions-in-one-vault-are-independent
  (let [[a1 b1] (established-pair)
        [a2 b2] (established-pair)]
    (session/close! a1)
    (session/close! b1)
    (let [[_ ct] (session/write-message! a2 (utf8 "still here"))]
      (is (bytes= (utf8 "still here") (second (session/read-message! b2 ct)))))
    (is (= 4 (count-entries)))))
