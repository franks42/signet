(ns signet.encryption
  "box v2 — authenticated encryption between signet identities, as a
   self-describing EDN value (design: docs/06-box-v2-design.md).

     (box   sender-kp recipient-pub plaintext)        → boxed (an EDN map)
     (box   sender-kp recipient-pub plaintext opts)
     (unbox recipient-kp-or-kps boxed)                → {:valid? … :plaintext …}
     (unbox recipient-kp-or-kps boxed opts)

   The box carries what the receiver needs: a 24-byte nonce (always) and,
   by default, the sender's and recipient's kids. The caller never sees
   or supplies a nonce. Kids may be Ed25519 or X25519 (Ed25519 identities
   are converted internally).

     {:type :signet/box :v 2
      :from \"urn:signet:pk:…\"  :to \"urn:signet:pk:…\"   ; optional, default on
      :aad  <any EDN>                                    ; optional caller context
      :nonce #bytes \"…\" :ct #bytes \"…\"}

   Keys are directional and unique per message:
     k = HKDF-SHA-256(X25519(sender, recipient), salt = nonce,
                      info = \"signet/box/v2\" ‖ sender_x25519 ‖ recipient_x25519)
   and the whole header (every field but :ct, cedn-canonical) is the AEAD's
   associated data. So a box cannot be reflected back to its sender, and no
   slot can be swapped, added or removed. Omitted kids are still bound
   through info.

   Slots are hints, not credentials. unbox reports :valid? (decrypts and
   authenticates). With {:from expected-kid-or-set} it also reports
   :verified? (the sender is who you expected), and :valid? then requires
   it. Whether that sender may do anything is policy: not box's job.
   unbox never throws on malformed input."
  (:require [cedn.core :as cedn]
            [signet.key :as key]
            [signet.vault :as vault]
            #?(:clj [signet.impl :as impl])))

#?(:clj
   (do
     (def ^:private ^"[B" info-prefix (.getBytes "signet/box/v2" "UTF-8"))
     (def ^:private header-slots #{:type :v :from :to :aad :nonce})

     (defn- x-pub
       "The X25519 public key bytes of a key record or a vault handle."
       [k]
       (:x (key/encryption-public-key (if (vault/handle? k) (vault/public-key k) k))))

     (defn- x-priv [k] (:d (key/encryption-private-key k)))

     (defn- dh
       "X25519 of our key (a keypair, or a handle: the DH then runs on
        material the vault lends for this call) with their X25519 public key
        bytes. The caller wipes the result."
       [ours their-xpk]
       (if (vault/handle? ours)
         (vault/x25519-dh ours their-xpk)
         (impl/x25519-dh (x-priv ours) their-xpk)))

     (defn- has-private?
       "A keypair with its private part, or a handle whose vault holds it."
       [k]
       (if (vault/handle? k)
         (some? (vault/handle (:vault k) (:kid k)))
         (some? (:d k))))

     (defn- wipe!
       "Zero a secret byte array whose purpose has ended. Impure."
       [bs]
       (when bs (java.util.Arrays/fill ^bytes bs (byte 0))))

     (defn- message-key!
       "HKDF key for one message, bound to its direction. Consumes (wipes)
        the DH output."
       [^bytes shared ^bytes nonce ^bytes sender-xpk ^bytes recipient-xpk]
       (let [info (byte-array (+ (alength info-prefix) 64))]
         (System/arraycopy info-prefix 0 info 0 (alength info-prefix))
         (System/arraycopy sender-xpk 0 info (alength info-prefix) 32)
         (System/arraycopy recipient-xpk 0 info (+ (alength info-prefix) 32) 32)
         (let [k (impl/hkdf-sha-256 shared nonce info 32)]
           (wipe! shared)
           k)))

     (def ^:private zero-nonce
       "AEAD nonce: always zero, because every message has its own key."
       (byte-array 12))))

(defn box
  "Encrypt plaintext bytes from sender-kp (a vault handle, or a keypair
   holding a private key) to recipient-pub (a public key, keypair or
   handle; Ed25519 or X25519). Returns the box as an EDN map. With a
   handle, the key agreement runs inside the vault.

   opts:
     :from?  include the sender's kid (default true)
     :to?    include the recipient's kid (default true)
     :aad    caller context, any CEDN-P EDN value: carried in the header,
             authenticated, NOT secret (it travels in the clear)

   Impure: draws a random nonce. Never touches the key store.
   Throws ex-info {:type ::no-private-key} when sender-kp has no private
   part; cedn's error when :aad is not canonical EDN (CEDN-P)."
  ([sender-kp recipient-pub plaintext]
   (box sender-kp recipient-pub plaintext nil))
  ([sender-kp recipient-pub plaintext {:keys [aad] from? :from? to? :to? :or {from? true to? true} :as opts}]
   #?@(:clj
       [(when-not (has-private? sender-kp)
          (throw (ex-info "box: sender key has no private part" {:type ::no-private-key})))
        (let [nonce  (impl/random-bytes 24)
              s-xpk  (x-pub sender-kp)
              r-xpk  (x-pub recipient-pub)
              header (cond-> {:type :signet/box :v 2 :nonce nonce}
                       from?                 (assoc :from (key/kid sender-kp))
                       to?                   (assoc :to (key/kid recipient-pub))
                       (contains? opts :aad) (assoc :aad aad))
              k      (message-key! (dh sender-kp r-xpk) nonce s-xpk r-xpk)
              ct     (try (impl/chacha20-poly1305-encrypt k zero-nonce plaintext
                                                          (cedn/canonical-bytes header))
                          (finally (wipe! k)))]
          (assoc header :ct ct))]
       :cljs
       [(throw (js/Error. "signet.encryption not yet implemented for ClojureScript"))])))

#?(:clj
   (do
     (defn- expected-set [e] (cond (set? e) e (some? e) #{e}))

     (defn- same-identity?
       "Do kid string kid and key record pub name the same X25519 key? The
        kid form (Ed25519 or X25519) does not matter."
       [kid pub]
       (when-let [p (vault/lookup kid)]
         (java.util.Arrays/equals (x-pub p) (x-pub pub))))

     (defn- recipient-candidates
       "The keys unbox may try: a vault id (every key that vault holds), a
        handle, a keypair, or a collection of handles and keypairs. Handles
        whose key is gone and keys without a private part are dropped."
       [x]
       (->> (cond (keyword? x)       (vault/handles x)
                  (vault/handle? x)  [x]
                  (map? x)           [x]
                  (coll? x)          x
                  :else              [])
            (filter has-private?)))

     (defn- invalid [reason & [extra]]
       (merge {:valid? false :error reason} extra))

     (defn- shape-error
       "Why boxed is not a well-formed v2 box, or nil."
       [boxed]
       (cond
         (not (map? boxed))                                  :malformed
         (not= :signet/box (:type boxed))                    :not-a-box
         (not= 2 (:v boxed))                                 :unsupported-version
         (seq (remove (conj header-slots :ct) (keys boxed))) :unknown-slot
         (not (and (bytes? (:nonce boxed)) (= 24 (alength ^bytes (:nonce boxed))))) :bad-nonce
         (not (and (bytes? (:ct boxed)) (<= 16 (alength ^bytes (:ct boxed)))))       :bad-ciphertext
         (and (contains? boxed :from) (not (string? (:from boxed)))) :bad-from
         (and (contains? boxed :to) (not (string? (:to boxed))))     :bad-to))

     (defn- try-open
       "Plaintext if the box opens for this recipient/sender pair, else nil."
       [boxed recipient sender]
       (let [nonce (:nonce boxed)
             k     (message-key! (dh recipient (x-pub sender))
                                 nonce (x-pub sender) (x-pub recipient))]
         (try
           (impl/chacha20-poly1305-decrypt k zero-nonce (:ct boxed)
                                           (cedn/canonical-bytes (dissoc boxed :ct)))
           (catch Exception _ nil)
           (finally (wipe! k)))))))

(defn unbox
  "Open a box. recipient-kp-or-kps is a vault id (e.g. :default: every
   key that vault holds), a handle, a keypair, or a collection of handles
   and keypairs. With several, the :to slot picks one, or each is tried
   when the box has no :to. Never throws: malformed input yields
   {:valid? false :error <reason>}.

   opts:
     :from  expected sender: a kid, or a set of kids. Needed when the box
            has no :from slot. With it the result has :verified?, and
            :valid? also requires it.
     :aad   expected caller context: must equal the box's :aad slot

   Result: {:valid? :verified? (with :from) :plaintext :from :to :aad :error}

   Never throws: malformed input gives {:valid? false :error <reason>}.
   Impure: reads the vault (and the key store) to resolve kids; never
   writes either."
  ([recipient-kp-or-kps boxed]
   (unbox recipient-kp-or-kps boxed nil))
  ([recipient-kp-or-kps boxed {expected-from :from :as opts}]
   #?(:clj
      (try
        (if-let [err (shape-error boxed)]
          (invalid err)
          (let [candidates (recipient-candidates recipient-kp-or-kps)
                to-kid     (:to boxed)
                recipients (if to-kid
                             (filter #(same-identity? to-kid %) candidates)
                             candidates)
                from-kid   (:from boxed)
                expected   (expected-set expected-from)
                senders    (if from-kid
                             (keep vault/lookup [from-kid])
                             (keep vault/lookup expected))
                aad-ok?    (or (not (contains? opts :aad))
                               (and (contains? boxed :aad)
                                    (= (cedn/canonical-str (:aad opts))
                                       (cedn/canonical-str (:aad boxed)))))]
            (cond
              (empty? candidates) (invalid :no-recipient-key)
              (empty? recipients) (invalid :not-for-these-keys {:to to-kid})
              (empty? senders)    (invalid (if from-kid :bad-from :unknown-sender))
              :else
              (if-let [[sender pt] (first (for [r recipients s senders
                                                :let [pt (try-open boxed r s)]
                                                :when pt]
                                            [s pt]))]
                (let [sender-kid (or from-kid (key/kid sender))
                      verified?  (when expected
                                   (boolean (some #(same-identity? % sender) expected)))
                      valid?     (and aad-ok? (if expected verified? true))]
                  (cond-> {:valid?    valid?
                           :plaintext pt
                           :from      sender-kid
                           :to        to-kid
                           :aad       (:aad boxed)}
                    expected                   (assoc :verified? verified?)
                    (not aad-ok?)              (assoc :error :aad-mismatch)
                    (and aad-ok? (not valid?)) (assoc :error :unexpected-sender)))
                (invalid :authentication-failed
                         (when expected {:verified? false}))))))
        (catch Exception e
          (invalid :malformed {:message (ex-message e)})))
      :cljs
      (throw (js/Error. "signet.encryption not yet implemented for ClojureScript")))))
