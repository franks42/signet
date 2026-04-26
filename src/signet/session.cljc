(ns signet.session
  "Forward-secret authenticated sessions via the Noise Protocol Framework.

   This namespace implements `Noise_KK_25519_ChaChaPoly_SHA256`: the KK
   handshake pattern from the Noise spec, with X25519 DH, ChaCha20-
   Poly1305 AEAD, and SHA-256 hashing. See `docs/05-noise-kk-session-
   design.md` for the design rationale and a Noise-mechanics walkthrough.

   The state is a pure-functional value. Each operation returns a new
   state plus produced bytes; no atoms, no mutation, no global state.
   Threading is the caller's concern.

   Typical use:

     ;; Both parties already know each other's static public keys
     ;; out-of-band (the K in K_K). Build a handshake state on each side.
     (def init-state (signet.session/initiator alice-kp bob-pub))
     (def resp-state (signet.session/responder bob-kp alice-pub))

     ;; Two-message handshake.
     (let [[init-state msg1] (write-message init-state app-payload-1)
           [resp-state recv1] (read-message resp-state msg1)
           [resp-state msg2] (write-message resp-state app-payload-2)
           [init-state recv2] (read-message init-state msg2)]
       (assert (established? init-state))
       (assert (established? resp-state))
       ;; Same API for transport messages: write/read just AEAD now.
       (let [[init-state ct] (write-message init-state ...)
             [resp-state pt] (read-message resp-state ct)]
         ...))

   Wire format:
     handshake msg1: e_pub(32) || encrypted-payload
     handshake msg2: e_pub(32) || encrypted-payload
     transport msg : encrypted-payload
   `encrypted-payload` is ChaCha20-Poly1305 ciphertext-with-tag (16-byte
   tag at end). Empty payloads are valid; the tag is still 16 bytes."
  (:require [signet.key :as key]
            #?(:clj [signet.impl.jvm :as jvm])))

;; ============================================================
;; Constants — protocol name and pattern fixed at compile time
;; ============================================================

(def ^:private ^String protocol-name
  "Identifies the concrete Noise instantiation. Mixed into the initial
   transcript hash, so any deviation in named primitives produces
   incompatible sessions. Length is exactly 32 bytes — the Noise spec
   sets h = protocol-name (no padding) when length ≤ 32."
  "Noise_KK_25519_ChaChaPoly_SHA256")

(def ^:private ^bytes protocol-name-bytes
  #?(:clj  (.getBytes protocol-name "UTF-8")
     :cljs (throw (ex-info "signet.session not yet implemented for ClojureScript" {}))))

;; ============================================================
;; Symmetric-state primitives (Noise spec §5.2)
;;
;; The handshake state evolves through four operations operating on
;; (ck, k, n, h):
;;   - MixHash:        h ← SHA-256(h ‖ data)
;;   - MixKey:         [ck, k] ← HKDF(salt=ck, ikm=DH-output, info="", 64)
;;                     n ← 0
;;   - EncryptAndHash: AEAD(k,n,h,plaintext) [if k] then MixHash(ct)
;;   - DecryptAndHash: AEAD-decrypt(k,n,h,ct) [if k] then MixHash(ct)
;;   - Split:          [t1,t2] ← HKDF(salt=ck, ikm="", info="", 64)
;;                     return cipher-states keyed by t1, t2
;;
;; These functions all take and return immutable maps. The map shape
;; for handshake state is documented at the public API below.
;; ============================================================

#?(:clj
   (defn- sha-256-bytes [^bytes data]
     (jvm/sha-256 data)))

#?(:clj
   (defn- mix-hash
     "h ← SHA-256(h ‖ data). The transcript hash binds every AEAD
      ciphertext to the entire history of the handshake — an attacker
      who reorders or substitutes prior messages will fail decryption
      on the next one."
     [{:keys [h] :as state} ^bytes data]
     (let [combined (byte-array (+ (alength ^bytes h) (alength data)))]
       (System/arraycopy ^bytes h 0 combined 0 (alength ^bytes h))
       (System/arraycopy data 0 combined (alength ^bytes h) (alength data))
       (assoc state :h (sha-256-bytes combined)))))

#?(:clj
   (defn- mix-key
     "Fold a DH output (or other ikm) into the chaining key and update
      the AEAD key. HKDF-Extract-then-Expand with the chaining key as
      salt: first 32 output bytes become new ck; last 32 become new k.
      Resets the nonce counter to zero."
     [{:keys [ck] :as state} ^bytes ikm]
     (let [out  (jvm/hkdf-sha-256 ikm ck (byte-array 0) 64)
           ck'  (java.util.Arrays/copyOfRange out 0 32)
           k'   (java.util.Arrays/copyOfRange out 32 64)]
       (assoc state :ck ck' :k k' :n 0))))

#?(:clj
   (defn- aead-nonce
     "Noise's AEAD nonce encoding (spec §5.1): 4 zero bytes followed by
      the 8-byte little-endian counter. Total 12 bytes for ChaCha-Poly."
     [^long n]
     (let [out (byte-array 12)]
       ;; Bytes 0-3 are zero (already set by byte-array). Bytes 4-11
       ;; carry the counter little-endian.
       (dotimes [i 8]
         (aset-byte out (+ 4 i) (unchecked-byte (bit-and (bit-shift-right n (* 8 i)) 0xff))))
       out)))

#?(:clj
   (defn- encrypt-and-hash
     "Encrypt `plaintext` under k (with h as AAD), increment n, then
      MixHash the produced ciphertext. If k is nil (no MixKey has run
      yet), passes plaintext through and just MixHashes it. Returns
      [new-state ciphertext-bytes]."
     [{:keys [k n h] :as state} ^bytes plaintext]
     (if k
       (let [ct       (jvm/chacha20-poly1305-encrypt k (aead-nonce n) plaintext h)
             state'   (-> state (assoc :n (inc n)) (mix-hash ct))]
         [state' ct])
       (let [state' (mix-hash state plaintext)]
         [state' plaintext]))))

#?(:clj
   (defn- decrypt-and-hash
     "Inverse of encrypt-and-hash. Throws on AEAD authentication
      failure — which signals tampering, wrong sender, or a wrong
      shared key from a botched DH. Important detail: MixHash is
      called with the CIPHERTEXT (not the plaintext) so both sides
      compute the same h regardless of who decrypted."
     [{:keys [k n h] :as state} ^bytes ciphertext]
     (if k
       (let [pt     (jvm/chacha20-poly1305-decrypt k (aead-nonce n) ciphertext h)
             state' (-> state (assoc :n (inc n)) (mix-hash ciphertext))]
         [state' pt])
       (let [state' (mix-hash state ciphertext)]
         [state' ciphertext]))))

#?(:clj
   (defn- split
     "Final step of the handshake: derive two independent transport
      cipher-state keys from the chaining key. Initiator's send key is
      t1, recv key is t2; responder's are flipped. After Split the
      symmetric state (ck, k, n, h) is no longer needed — only the two
      32-byte transport keys remain, each with its own monotonic
      nonce counter."
     [{:keys [ck role]}]
     (let [out (jvm/hkdf-sha-256 (byte-array 0) ck (byte-array 0) 64)
           t1  (java.util.Arrays/copyOfRange out 0 32)
           t2  (java.util.Arrays/copyOfRange out 32 64)
           [send recv] (case role
                         :initiator [t1 t2]
                         :responder [t2 t1])]
       {:phase :transport
        :role  role
        :send  {:k send :n 0}
        :recv  {:k recv :n 0}})))

;; ============================================================
;; Key extraction helpers — work with both X25519-native and Ed25519
;; identity keypairs (auto-converted via signet.key's birational map).
;; ============================================================

#?(:clj
   (defn- ->x25519-public-bytes
     "Extract the 32-byte X25519 public key from any signet key
      record. Ed25519 records are auto-converted via signet.key."
     [k]
     (:x (key/encryption-public-key k))))

#?(:clj
   (defn- dh
     "DH(local-priv, remote-pub) returning the 32-byte shared secret.
      Both inputs may be Ed25519 records — signet.key handles the
      X25519 conversion under the hood."
     [local-kp remote-pub]
     (:k (key/raw-shared-secret local-kp remote-pub))))

;; ============================================================
;; Initial state construction (Noise spec §5.3 init steps)
;; ============================================================

#?(:clj
   (defn- initial-symmetric-state
     []
     ;; Spec §5.2: if len(protocol-name) ≤ 32 bytes, h = pad-with-zeros
     ;; to 32. Our name is exactly 32, so h = protocol-name as bytes.
     ;; ck starts equal to h. k is nil (no AEAD key yet); n is 0.
     (let [name-copy (fn ^bytes [] (java.util.Arrays/copyOf ^bytes protocol-name-bytes 32))]
       {:h  (name-copy)
        :ck (name-copy)
        :k  nil
        :n  0})))

#?(:clj
   (defn- pre-message
     "Mix the static public keys into h in the order both sides agree
      on — initiator's static, then responder's static. Pre-message
      processing runs no DHs; it only updates the transcript hash so
      that the static identities are bound into every subsequent AEAD
      tag via h-as-AAD."
     [state init-static-pub-bytes resp-static-pub-bytes]
     (-> state
         (mix-hash init-static-pub-bytes)
         (mix-hash resp-static-pub-bytes))))

#?(:clj
   (defn- start-handshake
     "Common scaffolding for both initiator and responder: build the
      symmetric state, run pre-message MixHashes, mix in the prologue
      (defaults to empty bytes)."
     [role local-static-kp remote-static-pub prologue]
     (let [my-static-pub-bytes (->x25519-public-bytes local-static-kp)
           peer-static-pub-bytes (->x25519-public-bytes remote-static-pub)
           [init-pub resp-pub] (case role
                                 :initiator [my-static-pub-bytes peer-static-pub-bytes]
                                 :responder [peer-static-pub-bytes my-static-pub-bytes])]
       (-> (initial-symmetric-state)
           (assoc :phase             :handshake
                  :role              role
                  :pos               0
                  :local-static-kp   local-static-kp
                  :remote-static-pub remote-static-pub
                  :local-ephemeral-kp nil
                  :remote-ephemeral-pub nil)
           (pre-message init-pub resp-pub)
           (mix-hash (or prologue (byte-array 0)))))))

;; ============================================================
;; Public API
;; ============================================================

#?(:clj
   (defn initiator
     "Return a fresh Noise_KK initiator handshake state.

      `local-static-kp` — this side's long-term keypair (must contain
        a private key). Ed25519 keypairs are auto-converted to X25519.
      `remote-static-pub` — the peer's long-term public key, known
        out-of-band. Ed25519 keys are auto-converted.

      Optional opts:
        :prologue <bytes>  Application-supplied data mixed into the
                           initial transcript hash. Both sides must
                           supply the same prologue or the handshake
                           fails. Defaults to empty bytes.

      The returned state is opaque; threadable through write-message
      and read-message until established? returns true."
     ([local-static-kp remote-static-pub]
      (initiator local-static-kp remote-static-pub nil))
     ([local-static-kp remote-static-pub {:keys [prologue]}]
      (start-handshake :initiator local-static-kp remote-static-pub prologue))))

#?(:clj
   (defn responder
     "Return a fresh Noise_KK responder handshake state. See
      `initiator` for argument shape; the only difference is which
      role this side plays."
     ([local-static-kp remote-static-pub]
      (responder local-static-kp remote-static-pub nil))
     ([local-static-kp remote-static-pub {:keys [prologue]}]
      (start-handshake :responder local-static-kp remote-static-pub prologue))))

#?(:clj
   (defn established?
     "True iff the handshake has completed and transport messages may
      flow. Both sides reach this state after exchanging messages 1
      and 2 of the KK pattern."
     [state]
     (= :transport (:phase state))))

;; ============================================================
;; Handshake message processing (Noise spec §7.5 KK pattern)
;;
;; Pattern (with both static keys pre-shared):
;;   Msg 1 (init→resp): tokens "e, es, ss" + payload
;;   Msg 2 (resp→init): tokens "e, ee, se" + payload
;; After Msg 2 received, both sides Split() to transport mode.
;; ============================================================

#?(:clj
   (defn- write-message-1-initiator
     "Initiator's outbound message 1: 'e, es, ss, [payload]'
      - generate fresh ephemeral keypair
      - emit ephemeral public key (32 bytes), MixHash it
      - DH(my-ephemeral-priv, their-static-pub) → MixKey  (es)
      - DH(my-static-priv,    their-static-pub) → MixKey  (ss)
      - EncryptAndHash(payload). After 'es' the AEAD key exists,
        so the payload is now encrypted under the chained ck."
     [{:keys [local-static-kp remote-static-pub] :as state} payload]
     (let [eph-kp     (key/encryption-keypair)
           eph-pub-bs (:x eph-kp)
           state      (-> state
                          (assoc :local-ephemeral-kp eph-kp)
                          (mix-hash eph-pub-bs)                                       ; "e"
                          (mix-key (dh eph-kp remote-static-pub))                     ; "es"
                          (mix-key (dh local-static-kp remote-static-pub)))           ; "ss"
           [state ct] (encrypt-and-hash state (or payload (byte-array 0)))
           buf        (byte-array (+ 32 (alength ^bytes ct)))]
       (System/arraycopy eph-pub-bs 0 buf 0 32)
       (System/arraycopy ct 0 buf 32 (alength ^bytes ct))
       [(assoc state :pos 1) buf])))

#?(:clj
   (defn- read-message-1-responder
     "Responder reads message 1: same tokens 'e, es, ss', mirrored:
      - read ephemeral public key (32 bytes), MixHash it
      - DH(my-static-priv, their-ephemeral-pub) → MixKey (es)
      - DH(my-static-priv, their-static-pub)    → MixKey (ss)
      - DecryptAndHash(payload)."
     [{:keys [local-static-kp remote-static-pub] :as state} ^bytes msg]
     (when (< (alength msg) (+ 32 16))
       (throw (ex-info "Noise KK message 1 too short"
                       {:reason :reason/handshake-message-too-short
                        :length (alength msg)
                        :min    48})))
     (let [eph-pub-bs (java.util.Arrays/copyOfRange msg 0 32)
           remote-eph (key/encryption-public-key
                       {:type :signet/x25519-public-key :crv :X25519 :x eph-pub-bs})
           ct         (java.util.Arrays/copyOfRange msg 32 (alength msg))
           state      (-> state
                          (assoc :remote-ephemeral-pub remote-eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key (dh local-static-kp remote-eph))              ; "es"
                          (mix-key (dh local-static-kp remote-static-pub)))      ; "ss"
           [state pt] (decrypt-and-hash state ct)]
       [(assoc state :pos 1) pt])))

#?(:clj
   (defn- write-message-2-responder
     "Responder's outbound message 2: 'e, ee, se, [payload]'

      Token convention from the Noise spec: the first letter is the
      INITIATOR's key role, the second is the RESPONDER's. So:
        ee = DH(initiator-ephemeral, responder-ephemeral)
        se = DH(initiator-static,    responder-ephemeral)
      DH is symmetric; the responder computes each by combining one
      of its own private keys with the corresponding initiator public.

      - generate fresh ephemeral
      - emit it, MixHash
      - DH(my-ephemeral-priv, their-ephemeral-pub) → MixKey (ee) —
        forward secrecy enters here: ephemeral-ephemeral DH means the
        resulting key cannot be reconstructed from long-term keys alone.
      - DH(my-ephemeral-priv, their-static-pub) → MixKey (se) — note
        this uses *my ephemeral* against *their static*, not the
        other way around, because the token's `s` is the INITIATOR's
        static, not the local sender's.
      - EncryptAndHash(payload). After both DHs, Split into transport."
     [{:keys [remote-static-pub remote-ephemeral-pub] :as state} payload]
     (let [eph-kp     (key/encryption-keypair)
           eph-pub-bs (:x eph-kp)
           state      (-> state
                          (assoc :local-ephemeral-kp eph-kp)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key (dh eph-kp remote-ephemeral-pub))             ; "ee"
                          (mix-key (dh eph-kp remote-static-pub)))               ; "se"
           [state ct] (encrypt-and-hash state (or payload (byte-array 0)))
           buf        (byte-array (+ 32 (alength ^bytes ct)))]
       (System/arraycopy eph-pub-bs 0 buf 0 32)
       (System/arraycopy ct 0 buf 32 (alength ^bytes ct))
       [(split state) buf])))

#?(:clj
   (defn- read-message-2-initiator
     "Initiator reads message 2: 'e, ee, se':
      - read responder ephemeral pub, MixHash
      - DH(my-ephemeral-priv, their-ephemeral-pub) → MixKey (ee)
      - DH(my-static-priv, their-ephemeral-pub)     → MixKey (se)
      - DecryptAndHash(payload). Then Split."
     [{:keys [local-static-kp local-ephemeral-kp] :as state} ^bytes msg]
     (when (< (alength msg) (+ 32 16))
       (throw (ex-info "Noise KK message 2 too short"
                       {:reason :reason/handshake-message-too-short
                        :length (alength msg)
                        :min    48})))
     (let [eph-pub-bs (java.util.Arrays/copyOfRange msg 0 32)
           remote-eph (key/encryption-public-key
                       {:type :signet/x25519-public-key :crv :X25519 :x eph-pub-bs})
           ct         (java.util.Arrays/copyOfRange msg 32 (alength msg))
           state      (-> state
                          (assoc :remote-ephemeral-pub remote-eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key (dh local-ephemeral-kp remote-eph))           ; "ee"
                          (mix-key (dh local-static-kp remote-eph)))             ; "se"
           [state pt] (decrypt-and-hash state ct)]
       [(split state) pt])))

#?(:clj
   (defn- write-message-transport
     "AEAD-encrypt `plaintext` under the send cipher state. The send
      counter increments; no transcript hash is involved post-Split."
     [{:keys [send] :as state} ^bytes plaintext]
     (let [{:keys [k n]} send
           ct (jvm/chacha20-poly1305-encrypt k (aead-nonce n) plaintext nil)]
       [(assoc-in state [:send :n] (inc n)) ct])))

#?(:clj
   (defn- read-message-transport
     "Inverse of write-message-transport. Throws on AEAD auth failure."
     [{:keys [recv] :as state} ^bytes ciphertext]
     (let [{:keys [k n]} recv
           pt (jvm/chacha20-poly1305-decrypt k (aead-nonce n) ciphertext nil)]
       [(assoc-in state [:recv :n] (inc n)) pt])))

#?(:clj
   (defn write-message
     "Produce one outbound Noise message. During handshake the message
      includes the local ephemeral pub plus an AEAD-tagged payload;
      after Split, transport messages are pure AEAD ciphertext.

      `state` — handshake or transport state (from initiator/responder
                or a prior write-message/read-message).
      `plaintext` — application payload bytes. Empty (or nil) is fine.

      Returns [next-state ciphertext-bytes]. Throws if the state is not
      currently expecting an outbound message."
     [{:keys [phase role pos] :as state} plaintext]
     (cond
       (= phase :transport)
       (write-message-transport state (or plaintext (byte-array 0)))

       (and (= phase :handshake) (= role :initiator) (= pos 0))
       (write-message-1-initiator state plaintext)

       (and (= phase :handshake) (= role :responder) (= pos 1))
       (write-message-2-responder state plaintext)

       :else
       (throw (ex-info "Noise session: write-message in wrong phase"
                       {:reason :reason/wrong-message-phase
                        :phase  phase :role role :pos pos})))))

#?(:clj
   (defn read-message
     "Process one inbound Noise message. Inverse of write-message.
      Throws on AEAD authentication failure (tampered ciphertext,
      wrong peer, wrong shared key) or wrong message phase."
     [{:keys [phase role pos] :as state} ciphertext]
     (cond
       (= phase :transport)
       (read-message-transport state ciphertext)

       (and (= phase :handshake) (= role :responder) (= pos 0))
       (read-message-1-responder state ciphertext)

       (and (= phase :handshake) (= role :initiator) (= pos 1))
       (read-message-2-initiator state ciphertext)

       :else
       (throw (ex-info "Noise session: read-message in wrong phase"
                       {:reason :reason/wrong-message-phase
                        :phase  phase :role role :pos pos})))))
