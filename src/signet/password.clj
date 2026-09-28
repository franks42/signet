(ns signet.password
  "Password-derived keys, kept in the vault (docs/10-password-unlocking.md,
   slice 1). The caller holds a handle, never the key.

     (def h (password-key! password-bytes {:limits :moderate}))
     (seal h plaintext)                 → EDN map; carries the salt and cost
     (seal h plaintext {:aad x})        ; x: any CEDN-P value, authenticated, in the clear
     (open h sealed)                    → {:valid? … :plaintext … :aad …}; never throws
     (open password-bytes sealed)       ; derives the key again from the header

   Construction:

     root   = Argon2id(password, salt, 32 bytes, {:opslimit :memlimit})
     kid    = HMAC(root, \"signet/password/v1/kid\" ‖ 0x01), as urn:signet:password:…
     k_msg  = HKDF(root, salt = 24 random bytes, info = \"signet/password/v1/seal\")
     commit = HMAC(k_msg, \"signet/password/v1/commit\")
     ct     = ChaCha20-Poly1305(k_msg, nonce 0^96, plaintext, aad = cedn(header))

   The password is taken as bytes (the UTF-8 of what was typed) and wiped:
   it goes into the vault as a temporary entry (under the :sodium provider,
   straight into guarded memory) and is destroyed after Argon2id. A String
   cannot be wiped, so it is refused. The root key stays in the vault; under
   :sodium every secret above is a nacljc secret and never reaches the heap.

   Needs the libsodium backend (Argon2id is not in the JDK): on the JCA
   backend password-key! and password opening throw
   :signet.impl/unsupported, after wiping the password.

   Limits, stated plainly: a stolen sealed value can be attacked offline;
   only Argon2id's cost (about a second and 256 MiB per guess at
   :moderate) stands between a weak password and the plaintext."
  (:require [cedn.core :as cedn]
            [signet.encoding :as enc]
            [signet.impl :as impl]
            [signet.vault :as vault]))

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))

(def ^:private zero-nonce (byte-array 12))

(defn ^:no-doc limits-of
  "INTERNAL to signet.password and signet.vault.file: limits as
   {:opslimit :memlimit}, from a preset keyword or such a map. Pure.
   Throws ex-info {:type ::bad-option} otherwise, and
   :signet.impl/unsupported for a preset on the JCA backend."
  [limits]
  (cond
    (#{:interactive :moderate :sensitive} limits) (impl/argon2id-limits limits)
    (and (map? limits) (int? (:opslimit limits)) (int? (:memlimit limits))) (select-keys limits [:opslimit :memlimit])
    :else (throw (ex-info "password: :limits must be :interactive, :moderate, :sensitive or {:opslimit n :memlimit bytes}"
                          {:type ::bad-option :limits limits}))))

(defn- kid-of
  "The kid of root material: HKDF-Expand with the kid label. Pure for
   bytes; with a nacljc secret, impure: reads it."
  [root]
  (str "urn:signet:password:"
       (enc/bytes->base64url (impl/hmac-sha-256 root (byte-array (concat (utf8 "signet/password/v1/kid") [1]))))))

(defn- derive!
  "Adopt the password key for password, salt and limits into vault-id;
   returns its handle. Impure: writes the vault, consumes password."
  [vault-id ^bytes password ^bytes salt {:keys [opslimit memlimit] :as limits}]
  (let [root (vault/argon2id-material vault-id password salt limits)]
    (try
      (vault/adopt-symmetric! vault-id (kid-of root) :password root
                              {:salt (aclone salt) :opslimit opslimit :memlimit memlimit})
      (catch Throwable t (impl/destroy-material! root) (throw t)))))

(defn password-key!
  "A handle to the key derived from password (a byte array: the UTF-8 of
   what was typed) with Argon2id, kept in vault (default :default). The
   password array is wiped. The same password, salt and limits always give
   the same key and kid.

   opts:
     :salt    16 bytes (default: 16 random bytes)
     :limits  :interactive, :moderate (default), :sensitive, or
              {:opslimit n :memlimit bytes}
     :vault   the vault id (default :default)

   Impure: draws a salt from the CSPRNG when none is given, writes the
   vault, and consumes password (wipes the array, or destroys the secret).
   Throws ex-info {:type ::bad-password} unless password is a byte array or
   a nacljc secret (a
   String cannot be wiped), {:type ::bad-option} for a bad salt or limits,
   and :signet.impl/unsupported on the JCA backend (after wiping the
   password)."
  ([password] (password-key! password nil))
  ([password {:keys [salt limits vault] :or {limits :moderate vault :default}}]
   (when-not (vault/password-input? password)
     (throw (ex-info "password-key!: the password must be a byte array or a nacljc secret (a String cannot be wiped)"
                     {:type ::bad-password :got (str (type password))})))
   (try
     (let [limits (limits-of limits)
           salt   (or salt (impl/random-bytes 16))]
       (when-not (and (bytes? salt) (= 16 (alength ^bytes salt)))
         (throw (ex-info "password-key!: :salt must be 16 bytes" {:type ::bad-option})))
       (derive! vault password salt limits))
     (finally (impl/destroy-material! password)))))

(defn- meta! [h]
  (let [m (vault/shared-meta h)]
    (if (= :password (:kind m))
      m
      (throw (ex-info "Not a password key handle" {:type ::not-a-password-key :kid (:kid h)})))))

(defn- message-key
  "The one-message key, salted with nonce, derived from the root inside the
   call. with-root calls its argument with the root material: the vault
   lends a handle's (vault/with-material), or it is material in hand.
   Impure: reads the vault for a handle."
  [with-root ^bytes nonce]
  (with-root #(impl/hkdf-sha-256 % nonce (utf8 "signet/password/v1/seal") 32)))

(defn- handle-root
  "with-root for handle h. Impure: reads the vault."
  [h]
  (fn [f] (vault/with-material h f)))

(defn- commitment ^bytes [k] (impl/hmac-sha-256 k (utf8 "signet/password/v1/commit")))

(def ^:private header-slots #{:type :v :kid :salt :opslimit :memlimit :nonce :commit :aad})

(defn seal
  "Encrypt plaintext bytes under password key h. Returns an EDN map
   {:type :signet/password-sealed :v 1 :kid … :salt … :opslimit … :memlimit …
    :nonce … :commit … :aad? :ct …}. The salt and cost travel with it, so
   open can also start from the password alone.
   opts: :aad, caller context (any CEDN-P value): authenticated, NOT secret.
   Impure: draws a random nonce and reads the vault.
   Throws ex-info {:type ::not-a-password-key}, or the vault's errors."
  ([h plaintext] (seal h plaintext nil))
  ([h plaintext opts]
   (let [{:keys [salt opslimit memlimit]} (meta! h)
         nonce (impl/random-bytes 24)
         k     (message-key (handle-root h) nonce)]
     (try
       (let [header (cond-> {:type :signet/password-sealed :v 1 :kid (:kid h)
                             :salt salt :opslimit opslimit :memlimit memlimit
                             :nonce nonce :commit (commitment k)}
                      (contains? opts :aad) (assoc :aad (:aad opts)))
             ct     (impl/chacha20-poly1305-encrypt k zero-nonce plaintext (cedn/canonical-bytes header))]
         (assoc header :ct ct))
       (finally (impl/destroy-material! k))))))

(defn- shape-error [sealed]
  (cond
    (not (map? sealed))                                   :malformed
    (not= :signet/password-sealed (:type sealed))         :not-password-sealed
    (not= 1 (:v sealed))                                  :unsupported-version
    (seq (remove (conj header-slots :ct) (keys sealed)))  :unknown-slot
    (not (string? (:kid sealed)))                         :bad-kid
    (not (and (bytes? (:salt sealed)) (= 16 (alength ^bytes (:salt sealed))))) :bad-salt
    (not (and (int? (:opslimit sealed)) (int? (:memlimit sealed)))) :bad-limits
    (not (and (bytes? (:nonce sealed)) (= 24 (alength ^bytes (:nonce sealed))))) :bad-nonce
    (not (and (bytes? (:commit sealed)) (= 32 (alength ^bytes (:commit sealed))))) :bad-commit
    (not (and (bytes? (:ct sealed)) (<= 16 (alength ^bytes (:ct sealed)))))     :bad-ciphertext))

(defn- open-with-root
  "Open sealed with the root that with-root lends, known to have kid.
   :wrong-key when kid is not the sealed value's."
  [with-root kid sealed opts]
  (if (not= kid (:kid sealed))
    {:valid? false :error :wrong-key}
    (let [k (message-key with-root (:nonce sealed))]
      (try
        (if-not (java.security.MessageDigest/isEqual (commitment k) (:commit sealed))
          {:valid? false :error :commitment-mismatch}
          (let [pt (try (impl/chacha20-poly1305-decrypt k zero-nonce (:ct sealed)
                                                        (cedn/canonical-bytes (dissoc sealed :ct)))
                        (catch Exception _ nil))
                aad-ok? (or (not (contains? opts :aad))
                            (and (contains? sealed :aad)
                                 (= (cedn/canonical-str (:aad opts)) (cedn/canonical-str (:aad sealed)))))]
            (cond
              (nil? pt)     {:valid? false :error :authentication-failed}
              (not aad-ok?) {:valid? false :error :aad-mismatch :aad (:aad sealed)}
              :else         {:valid? true :plaintext pt :aad (:aad sealed)})))
        (finally (impl/destroy-material! k))))))

(defn open
  "Open a value made by seal. key-or-password is the password key's handle,
   or the password itself (a byte array or a nacljc secret, consumed): then the key is derived
   again from the salt and cost in the header (in the :default vault, or
   opts :vault), used, and destroyed.
   Never throws: {:valid? false :error <reason>} for anything wrong, with
   :wrong-password when a password gives another key, :wrong-key for a
   handle of another key.
   opts: :aad, expected caller context (must equal the :aad slot); :vault.
   Result: {:valid? :plaintext :aad :error}.
   Impure: reads the vault; with a password, also writes it (temporarily)
   and wipes the password array."
  ([key-or-password sealed] (open key-or-password sealed nil))
  ([key-or-password sealed opts]
   (try
     (if-let [err (shape-error sealed)]
       (do (when (vault/password-input? key-or-password) (impl/destroy-material! key-or-password))
           {:valid? false :error err})
       (if (vault/password-input? key-or-password)
         ;; derive the root, use it and destroy it: nothing is adopted into
         ;; the vault (an existing handle with the same kid stays untouched)
         (let [root (try (vault/argon2id-material (:vault opts :default) key-or-password (:salt sealed)
                                                  (select-keys sealed [:opslimit :memlimit]))
                         (finally (impl/destroy-material! key-or-password)))]
           (try
             (let [r (open-with-root (fn [f] (f root)) (kid-of root) sealed opts)]
               (if (= :wrong-key (:error r)) {:valid? false :error :wrong-password} r))
             (finally (impl/destroy-material! root))))
         (do (meta! key-or-password)
             (open-with-root (handle-root key-or-password) (:kid key-or-password) sealed opts))))
     (catch Exception e
       {:valid? false :error :malformed :message (ex-message e)}))))
