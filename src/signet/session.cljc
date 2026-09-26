(ns signet.session
  "Forward-secret authenticated sessions via the Noise Protocol Framework.

   This namespace implements `Noise_KK_25519_ChaChaPoly_SHA256`: the KK
   handshake pattern from the Noise spec, with X25519 DH, ChaCha20-
   Poly1305 AEAD, and SHA-256 hashing. See `docs/05-noise-kk-session-
   design.md` for the design rationale and a Noise-mechanics walkthrough,
   and `docs/08-sessions-on-handles-plan.md` for how secrets are kept.

   Secrets live in the vault, never in the state. The chaining key, the
   handshake key, the transport keys and the ephemeral keys are vault
   session entries (in the vault of the local static key), and a state
   holds only their handles plus public values: printing or logging a
   state shows nothing secret. Each state is single-use; write-message!
   and read-message! return the next one and destroy the entries only the
   consumed state needed.

   A session must be closed: close! (from any of its states) destroys all
   its secrets; with-conclave closes it when a block exits. A session that
   is never closed leaves its secrets in the vault
   (vault/session-entry-count shows them).

   Typical use:

     ;; Both parties already know each other's static public keys
     ;; out-of-band (the K in K_K). Each side's identity is a vault handle.
     (with-conclave [i (initiator alice-handle bob-kid)]
       (let [[i msg1] (write-message! i app-payload-1)
             ;; … send msg1, receive msg2 …
             [i recv2] (read-message! i msg2)]
         (assert (established? i))
         ;; Same API for transport messages: write/read are just AEAD now.
         (let [[i ct] (write-message! i data)] …)))

   Wire format:
     handshake msg1: e_pub(32) || encrypted-payload
     handshake msg2: e_pub(32) || encrypted-payload
     transport msg : encrypted-payload
   `encrypted-payload` is ChaCha20-Poly1305 ciphertext-with-tag (16-byte
   tag at end). Empty payloads are valid; the tag is still 16 bytes."
  (:require [signet.key :as key]
            [signet.vault :as vault]
            #?(:clj [signet.impl :as impl])))

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
;; Session secrets: tracking, cleanup, single use
;;
;; Every vault entry a call creates is recorded in *created* (bound by
;; consume!). When the call succeeds, consume! destroys the entries that
;; neither the next state nor anything after it needs; when it fails, it
;; destroys everything the call created, so the consumed state stays
;; usable and the vault gains nothing.
;; ============================================================

(def ^:private ^:dynamic *created*
  "A volatile collecting the vault handles created by the current
   write/read call. Bound by consume! only."
  nil)

(defn- created!
  "Record handles as created by the current call; returns the first."
  [h & more]
  (when-let [c *created*] (vswap! c into (cons h more)))
  h)

(defn- live-handles
  "The vault handles a state holds (never the caller's static key)."
  [state]
  (set (remove nil? [(when (vault/handle? (:ck state)) (:ck state))
                     (:k state)
                     (get-in state [:local-ephemeral :handle])
                     (get-in state [:send :k])
                     (get-in state [:recv :k])])))

#?(:clj
   (defn- destroy-quietly!
     "Destroy h, leaving it to close! if that fails (for example a secret
      still in use by a racing call on another thread)."
     [h]
     (try (vault/destroy! h) (catch Exception _ nil))))

#?(:clj
   (defn- fresh-marker
     "A one-shot marker for a session state value. Every state
      write-message! / read-message! returns gets a fresh one."
     []
     ;; A Clojure atom, not AtomicBoolean: bb does not expose the latter,
     ;; and compare-and-set! is an atomic CAS on both platforms.
     (atom false)))

#?(:clj
   (defn- throw-stale []
     (throw (ex-info "Stale session state: it was already used. Use the state returned by the previous write-message!/read-message!"
                     {:type ::stale-session-state}))))

#?(:clj
   (defn- throw-closed []
     (throw (ex-info "The session was closed (close! or the end of with-conclave)"
                     {:type ::session-closed}))))

#?(:clj
   (defn- check-state [state]
     (when-not (and (instance? clojure.lang.Atom (:consumed state))
                    (instance? clojure.lang.Atom (:closed state)))
       (throw (ex-info "Not a signet session state (missing single-use marker)"
                       {:type ::not-a-session-state})))
     state))

#?(:clj
   (defn- consume!
     "Run op (which returns [next-state output]) on state, then mark state
      consumed; return [next-state-with-fresh-marker output].

      A state is single-use: using a consumed state again throws
      ::stale-session-state. Reusing a sending state would reuse its AEAD
      nonce (plaintext XOR leak, forgeries); reusing a receiving state
      would accept a replay. The marker is set only after op succeeds, so
      a failed read (forged or tampered message) leaves the state usable.
      Under a race, compare-and-set lets exactly one caller win; the
      losers' outputs and vault entries are discarded, never returned.
      After a win, the entries the consumed state held that the next
      state does not are destroyed (replaced chaining keys, ephemerals).
      Impure: mutates the marker of the state passed in, writes the vault."
     [state op]
     (check-state state)
     (let [m (:consumed state)]
       (when @(:closed state) (throw-closed))
       (when @m (throw-stale))
       (let [created (volatile! [])
             [next-state out]
             (try (binding [*created* created] (op))
                  (catch Exception e
                    (run! destroy-quietly! @created)
                    ;; a racing winner may have destroyed what op was using
                    (when @m (throw-stale))
                    (throw e)))]
         (when-not (compare-and-set! m false true)
           (run! destroy-quietly! @created)
           (throw-stale))
         (let [keep (live-handles next-state)]
           (doseq [h (concat @created (live-handles state)) :when (not (keep h))]
             (destroy-quietly! h)))
         (when @(:closed state)
           ;; closed while op ran: its new entries may postdate close!
           (run! destroy-quietly! (live-handles next-state))
           (throw-closed))
         [(assoc next-state :consumed (fresh-marker)) out]))))

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
;; h is public. ck starts public (the protocol name) and is a vault handle
;; from the first MixKey on; k and the transport keys are always handles.
;; ============================================================

#?(:clj
   (defn- open-aead
     "AEAD-decrypt a session message under key handle k. Every failure
      (forged, tampered, replayed out of order, wrong key) becomes one
      backend-independent error, {:type ::authentication-failed}, instead
      of whatever the JCA or libsodium backend throws."
     [k nonce ciphertext aad]
     (try
       (vault/aead-decrypt k nonce ciphertext aad)
       (catch Exception e
         (throw (ex-info "Noise session: message authentication failed"
                         {:type ::authentication-failed} e))))))

#?(:clj
   (defn- sha-256-bytes [^bytes data]
     (impl/sha-256 data)))

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
   (defn- mix-key!
     "Fold a DH output into the chaining key and set a new AEAD key:
      HKDF with the chaining key as salt; the first 32 output bytes become
      the new ck, the last 32 the new k. Resets the nonce counter to zero.
      Both live in the vault. Consumes and destroys ikm (a DH output,
      used once). Impure: writes the vault."
     [{:keys [ck vault session-id] :as state} ikm]
     (let [[ck' k'] (vault/hkdf-pair! vault session-id ck ikm)]
       (created! ck' k')
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
       (let [ct       (vault/aead-encrypt k (aead-nonce n) plaintext h)
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
       (let [pt     (open-aead k (aead-nonce n) ciphertext h)
             state' (-> state (assoc :n (inc n)) (mix-hash ciphertext))]
         [state' pt])
       (let [state' (mix-hash state ciphertext)]
         [state' ciphertext]))))

#?(:clj
   (defn- split!
     "Final step of the handshake: derive the two transport keys from the
      chaining key, as vault entries. Initiator's send key is t1, recv key
      is t2; responder's are flipped. The returned transport state no
      longer holds ck, k or the ephemeral, so consume! destroys them:
      that is where forward secrecy comes from. Impure: writes the vault."
     [{:keys [ck role vault session-id closed]}]
     (let [[t1 t2] (vault/hkdf-pair! vault session-id ck (byte-array 0))
           _       (created! t1 t2)
           [send recv] (case role
                         :initiator [t1 t2]
                         :responder [t2 t1])]
       {:phase      :transport
        :role       role
        :vault      vault
        :session-id session-id
        :closed     closed
        :send       {:k send :n 0}
        :recv       {:k recv :n 0}})))

;; ============================================================
;; Keys: identity keys (vault handles, or deprecated key records) and
;; ephemerals (vault session entries)
;; ============================================================

#?(:clj
   (do
     ;; Ephemeral keys are their own types, so code can tell them apart
     ;; from identity keys: dh/edh check them, and signet.key/register!
     ;; refuses them. Private to this namespace. The local ephemeral's
     ;; private key is a vault session entry; the record holds its handle.
     (defrecord EphemeralKeyPair [type crv x handle])
     (defrecord EphemeralPublicKey [type crv x])))

#?(:clj
   (def ^:private ephemeral-types
     #{:signet/ephemeral-x25519-keypair :signet/ephemeral-x25519-public-key}))

#?(:clj
   (defn- ephemeral? [k] (contains? ephemeral-types (:type k))))

#?(:clj
   (defn- ->x25519-public-bytes
     "The 32-byte X25519 public key of a key record, an ephemeral, or a
      vault handle. X25519 keys are used as-is; Ed25519 identity keys go
      through signet.key's conversion."
     [k]
     (cond
       (vault/handle? k) (recur (vault/public-key k))
       :else
       (case (:type k)
         (:signet/x25519-public-key :signet/x25519-keypair
                                    :signet/ephemeral-x25519-keypair :signet/ephemeral-x25519-public-key) (:x k)
         (:x (key/encryption-public-key k))))))

#?(:clj
   (defn- ->x25519-private-bytes
     "The 32-byte X25519 private key of a static X25519 keypair record or,
      via conversion, of a static Ed25519 keypair record (deprecated
      inputs; handles never expose their key)."
     [k]
     (case (:type k)
       :signet/x25519-keypair (:d k)
       (:d (key/encryption-private-key k)))))

#?(:clj
   (defn- fresh-ephemeral
     "A new X25519 ephemeral key, born in the session's vault as a session
      entry. Never on the vault's public side, never listed by handles;
      destroyed once the handshake no longer needs it. Callers of the
      public API never see it. Impure: draws from the CSPRNG and writes
      the vault."
     [vault-id session-id]
     (let [[h pub] (vault/generate-ephemeral! vault-id session-id)]
       (created! h)
       (->EphemeralKeyPair :signet/ephemeral-x25519-keypair :X25519 pub h))))

#?(:clj
   (defn- x25519-dh*
     "The raw X25519 computation behind dh and edh. A local ephemeral or
      handle computes inside the vault (the result is material that
      mix-key! consumes: bytes, or a nacljc secret under :sodium); a
      deprecated key record computes on the backend directly. Nothing is
      registered anywhere."
     [local remote-pub]
     (let [their (->x25519-public-bytes remote-pub)]
       (cond
         (instance? EphemeralKeyPair local) (vault/x25519-dh (:handle local) their)
         (vault/handle? local)              (vault/x25519-dh local their)
         :else                              (impl/x25519-dh (->x25519-private-bytes local) their)))))

#?(:clj
   (defn- dh
     "Static-static DH — Noise token ss. Returns the shared secret, which
      mix-key! consumes and destroys. Never registers keys.
      Throws ::ephemeral-in-dh if either side is ephemeral: that is edh's
      job, and mixing them up must fail loudly, not silently."
     [local-static remote-static-pub]
     (when (or (ephemeral? local-static) (ephemeral? remote-static-pub))
       (throw (ex-info "dh is for static keys only (Noise ss); use edh for es/ee/se"
                       {:type ::ephemeral-in-dh})))
     (x25519-dh* local-static remote-static-pub)))

#?(:clj
   (defn- edh
     "Ephemeral DH — Noise tokens es, ee, se: at least one side is an
      ephemeral key. Never registers keys; the output is consumed and
      destroyed by mix-key!, and the local ephemeral is destroyed after
      Split. Ephemerals never leave this namespace. Throws
      ::no-ephemeral-in-edh if neither side is ephemeral (that is dh)."
     [local remote-pub]
     (when-not (or (ephemeral? local) (ephemeral? remote-pub))
       (throw (ex-info "edh needs an ephemeral key on at least one side (Noise es/ee/se); use dh for ss"
                       {:type ::no-ephemeral-in-edh})))
     (x25519-dh* local remote-pub)))

;; ============================================================
;; Initial state construction (Noise spec §5.3 init steps)
;; ============================================================

#?(:clj
   (defn- initial-symmetric-state
     []
     ;; Spec §5.2: if len(protocol-name) ≤ 32 bytes, h = pad-with-zeros
     ;; to 32. Our name is exactly 32, so h = protocol-name as bytes.
     ;; ck starts equal to h (public). k is nil (no AEAD key yet); n is 0.
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
   (defn- check-local-static
     "The local static key: a vault handle for a key its vault holds (an
      X25519 or Ed25519 identity), or a deprecated key record with its
      private part. Returns the vault id the session's secrets go into."
     [local opts]
     (cond
       (vault/handle? local)
       (do (when-not (vault/handle (:vault local) (:kid local))
             (throw (ex-info "Noise session: the vault does not hold this key as an identity (destroyed, never held, or a session secret)"
                             {:type ::no-private-key :kid (:kid local)})))
           (when-not (#{:ed25519 :x25519} (vault/algorithm local))
             (throw (ex-info "Noise session: the local static key must be an X25519 or Ed25519 key"
                             {:type ::no-private-key :kid (:kid local)})))
           (:vault local))

       (:d local)
       (:vault opts :default)

       :else
       (throw (ex-info "Noise session: the local static key needs its private part"
                       {:type ::no-private-key :key-type (:type local)})))))

#?(:clj
   (defn- resolve-remote
     "The peer's static public key: a key record, or a kid resolved through
      the vault (its public side, else parsed from the kid)."
     [vault-id remote]
     (if (string? remote)
       (or (vault/lookup vault-id remote)
           (throw (ex-info "Noise session: cannot resolve the peer's kid"
                           {:type ::unknown-peer :kid remote})))
       remote)))

#?(:clj
   (defn- start-handshake
     "Common scaffolding for both initiator and responder: build the
      symmetric state, mix in the prologue (defaults to empty bytes), then
      run the pre-message MixHashes."
     [role local-static remote-static prologue opts]
     (let [vault-id              (check-local-static local-static opts)
           remote-static-pub     (resolve-remote vault-id remote-static)
           my-static-pub-bytes   (->x25519-public-bytes local-static)
           peer-static-pub-bytes (->x25519-public-bytes remote-static-pub)
           [init-pub resp-pub] (case role
                                 :initiator [my-static-pub-bytes peer-static-pub-bytes]
                                 :responder [peer-static-pub-bytes my-static-pub-bytes])]
       (-> (initial-symmetric-state)
           (assoc :phase             :handshake
                  :role              role
                  :consumed          (fresh-marker)
                  :closed            (atom false)
                  :vault             vault-id
                  :session-id        (random-uuid)
                  :pos               0
                  :local-static      local-static
                  :remote-static-pub remote-static-pub
                  :local-ephemeral   nil
                  :remote-ephemeral-pub nil)
           ;; Noise spec §5.3 Initialize: MixHash(prologue) first, then
           ;; the pre-message public keys.
           (mix-hash (or prologue (byte-array 0)))
           (pre-message init-pub resp-pub)))))

;; ============================================================
;; Public API
;; ============================================================

#?(:clj
   (defn initiator
     "Return a fresh Noise_KK initiator handshake state.

      Impure: draws a random session id (a read of the random generator);
      it writes nothing: the first secrets enter the vault with the first
      message. Reads the vault to check local-static and resolve a kid.
      Throws ex-info {:type ::no-private-key} when local-static is not a
      key its vault holds as an identity (or a record without its private
      part), and {:type ::unknown-peer} for a kid that cannot be resolved.

      `local-static` — this side's long-term key: a vault handle for an
        X25519 or Ed25519 key. The session's secrets are kept in that
        handle's vault. (A key record with its private part still works,
        deprecated; its session secrets go to the :vault option's vault,
        default :default.)
      `remote-static` — the peer's long-term public key, known out of
        band: a public key record, or its kid. Ed25519 keys are
        auto-converted.

      Optional opts:
        :prologue <bytes>  Application-supplied data mixed into the
                           initial transcript hash. Both sides must
                           supply the same prologue or the handshake
                           fails. Defaults to empty bytes.
        :vault <id>        Only for a key-record local-static.

      The returned state is opaque; thread it through write-message! and
      read-message! until established? returns true, and close! it (or
      use with-conclave) when done."
     ([local-static remote-static]
      (initiator local-static remote-static nil))
     ([local-static remote-static {:keys [prologue] :as opts}]
      (start-handshake :initiator local-static remote-static prologue opts))))

#?(:clj
   (defn responder
     "Return a fresh Noise_KK responder handshake state. See
      `initiator` for argument shape, purity and errors; the only
      difference is which role this side plays."
     ([local-static remote-static]
      (responder local-static remote-static nil))
     ([local-static remote-static {:keys [prologue] :as opts}]
      (start-handshake :responder local-static remote-static prologue opts))))

#?(:clj
   (defn established?
     "True iff the handshake has completed and transport messages may
      flow. Both sides reach this state after exchanging messages 1
      and 2 of the KK pattern. Pure."
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
     [{:keys [local-static remote-static-pub vault session-id] :as state} payload]
     (let [eph        (fresh-ephemeral vault session-id)
           eph-pub-bs (:x eph)
           state      (-> state
                          (assoc :local-ephemeral eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key! (edh eph remote-static-pub))                 ; "es"
                          (mix-key! (dh local-static remote-static-pub)))        ; "ss"
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
     [{:keys [local-static remote-static-pub] :as state} ^bytes msg]
     (when (< (alength msg) (+ 32 16))
       (throw (ex-info "Noise KK message 1 too short"
                       {:type   ::handshake-message-too-short
                        :length (alength msg)
                        :min    48})))
     (let [eph-pub-bs (java.util.Arrays/copyOfRange msg 0 32)
           remote-eph (->EphemeralPublicKey :signet/ephemeral-x25519-public-key :X25519 eph-pub-bs)
           ct         (java.util.Arrays/copyOfRange msg 32 (alength msg))
           state      (-> state
                          (assoc :remote-ephemeral-pub remote-eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key! (edh local-static remote-eph))               ; "es"
                          (mix-key! (dh local-static remote-static-pub)))        ; "ss"
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
     [{:keys [remote-static-pub remote-ephemeral-pub vault session-id] :as state} payload]
     (let [eph        (fresh-ephemeral vault session-id)
           eph-pub-bs (:x eph)
           state      (-> state
                          (assoc :local-ephemeral eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key! (edh eph remote-ephemeral-pub))              ; "ee"
                          (mix-key! (edh eph remote-static-pub)))                ; "se"
           [state ct] (encrypt-and-hash state (or payload (byte-array 0)))
           buf        (byte-array (+ 32 (alength ^bytes ct)))]
       (System/arraycopy eph-pub-bs 0 buf 0 32)
       (System/arraycopy ct 0 buf 32 (alength ^bytes ct))
       [(split! state) buf])))

#?(:clj
   (defn- read-message-2-initiator
     "Initiator reads message 2: 'e, ee, se':
      - read responder ephemeral pub, MixHash
      - DH(my-ephemeral-priv, their-ephemeral-pub) → MixKey (ee)
      - DH(my-static-priv, their-ephemeral-pub)     → MixKey (se)
      - DecryptAndHash(payload). Then Split."
     [{:keys [local-static local-ephemeral] :as state} ^bytes msg]
     (when (< (alength msg) (+ 32 16))
       (throw (ex-info "Noise KK message 2 too short"
                       {:type   ::handshake-message-too-short
                        :length (alength msg)
                        :min    48})))
     (let [eph-pub-bs (java.util.Arrays/copyOfRange msg 0 32)
           remote-eph (->EphemeralPublicKey :signet/ephemeral-x25519-public-key :X25519 eph-pub-bs)
           ct         (java.util.Arrays/copyOfRange msg 32 (alength msg))
           state      (-> state
                          (assoc :remote-ephemeral-pub remote-eph)
                          (mix-hash eph-pub-bs)                                  ; "e"
                          (mix-key! (edh local-ephemeral remote-eph))            ; "ee"
                          (mix-key! (edh local-static remote-eph)))              ; "se"
           [state pt] (decrypt-and-hash state ct)]
       [(split! state) pt])))

#?(:clj
   (defn- write-message-transport
     "AEAD-encrypt `plaintext` under the send key. The send counter
      increments; no transcript hash is involved post-Split."
     [{:keys [send] :as state} ^bytes plaintext]
     (let [{:keys [k n]} send
           ct (vault/aead-encrypt k (aead-nonce n) plaintext nil)]
       [(assoc-in state [:send :n] (inc n)) ct])))

#?(:clj
   (defn- read-message-transport
     "Inverse of write-message-transport. Throws on AEAD auth failure."
     [{:keys [recv] :as state} ^bytes ciphertext]
     (let [{:keys [k n]} recv
           pt (open-aead k (aead-nonce n) ciphertext nil)]
       [(assoc-in state [:recv :n] (inc n)) pt])))

#?(:clj
   (defn- write-message*
     "Produce one outbound Noise message: [next-state ciphertext-bytes].
      Throws if the state is not currently expecting an outbound message."
     [{:keys [phase role pos] :as state} plaintext]
     (cond
       (= phase :transport)
       (write-message-transport state (or plaintext (byte-array 0)))

       (and (= phase :handshake) (= role :initiator) (= pos 0))
       (write-message-1-initiator state plaintext)

       (and (= phase :handshake) (= role :responder) (= pos 1))
       (write-message-2-responder state plaintext)

       :else
       (throw (ex-info "Noise session: write-message! in wrong phase"
                       {:type   ::wrong-message-phase
                        :phase  phase :role role :pos pos})))))

#?(:clj
   (defn- read-message*
     "Process one inbound Noise message. Inverse of write-message*.
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
       (throw (ex-info "Noise session: read-message! in wrong phase"
                       {:type   ::wrong-message-phase
                        :phase  phase :role role :pos pos})))))

#?(:clj
   (defn write-message!
     "Produce one outbound Noise message: returns [next-state ciphertext].

      Impure: consumes `state` (each state value is single-use; always
      continue with the returned next-state), writes the vault (new
      session secrets; those no longer needed are destroyed), and draws a
      fresh ephemeral key for handshake messages.

      Throws ex-info {:type ::stale-session-state} when `state` was already
      used (instead of reusing its nonce; see consume!),
      {:type ::session-closed} after close!,
      {:type ::wrong-message-phase} when the state is not expecting an
      outbound message, and {:type ::not-a-session-state} for anything
      that is not a session state.

      `plaintext` — application payload bytes. Empty (or nil) is fine.
      During the handshake the message carries the local ephemeral public
      key plus an AEAD-tagged payload; after Split, transport messages are
      pure AEAD ciphertext."
     [state plaintext]
     (consume! state #(write-message* state plaintext))))

#?(:clj
   (defn read-message!
     "Process one inbound Noise message: returns [next-state plaintext].

      Impure: a successful read consumes `state` (single-use, like
      write-message!) and writes the vault. A failed read throws, leaves
      `state` usable for the genuine message, and leaves no new secret in
      the vault.

      Throws ex-info {:type ::authentication-failed} for a forged,
      tampered or misdirected message (the same on every backend),
      {:type ::stale-session-state} when `state` was already used (which
      also refuses a replayed ciphertext), {:type ::session-closed},
      {:type ::handshake-message-too-short}, {:type ::wrong-message-phase},
      and {:type ::not-a-session-state}."
     [state ciphertext]
     (consume! state #(read-message* state ciphertext))))

#?(:clj
   (defn close!
     "Close the session `state` belongs to: destroy every secret it has in
      the vault, whichever state holds it, and refuse any later use of any
      of its states ({:type ::session-closed}). Works from any state of the
      session: the first, a consumed one, or the latest. Closing again is a
      no-op. Returns nil.
      Impure: writes the vault and the session's closed flag.
      Throws ex-info {:type ::not-a-session-state} for anything else."
     [state]
     (check-state state)
     (reset! (:closed state) true)
     (vault/destroy-session! (:vault state) (:session-id state))
     nil))

#?(:clj
   (defmacro with-conclave
     "(with-conclave [s (initiator my-handle peer-kid)] body…)

      Evaluate body with s bound to a session state, then close! the
      session, also when body throws. The body threads states as usual;
      closing from the state bound here closes the whole session, however
      many messages followed.

      A conclave is a closed meeting (Latin con clave, \"with a key\"): a
      room locked with a key, like a session whose keys live in the vault
      and are destroyed when it ends. Not to be confused with an enclave,
      where a vault's secrets live.

      Use it when one block of code runs the whole session: a request and
      its reply, a script, a test, or a helper that runs a session per
      call. A session that outlives a block (one kept per connection)
      needs an explicit close!, for example when the connection closes.
      Any state or lazy value that escapes the block and is used later
      throws {:type ::session-closed}."
     [[sym init] & body]
     `(let [~sym ~init]
        (try ~@body (finally (close! ~sym))))))
