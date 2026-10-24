(ns signet.vault
  "Secrets by reference (design: docs/07-secret-handles-design.md).

   Code holds handles, never secret bytes. A handle is an immutable value,
     #signet.vault.KeyHandle{:type :signet/key-handle :kid \"urn:signet:pk:…\" :vault :default}
   that names a key and the vault holding it. It is safe to print, log,
   serialise and send: it contains nothing secret. A handle is a reference,
   not a credential: anyone can build one; the vault decides what it may do.

   A vault has two sides, indexed by the same kid:
     public side  public keys: everyone's (peers' and your own). (lookup kid)
     secret side  private keys you hold, inside a provider.       (handle kid)

   Vaults are registered under ids; :default exists from the start with the
   :memory provider. An operation resolves its vault from the handle's
   :vault at call time; an unknown id throws ::unknown-vault.

     (generate-signing-key!)            → handle (the key is born in the vault)
     (generate-encryption-key!)         → handle
     (import-signing-key! seed)         → handle; wipes seed (handle with care)
     (import-encryption-key! sk)        → handle; wipes sk
     (export-secret h {:i-understand :exposes-secret}) → bytes (the only way out)
     (destroy! h)                       → wipes and removes the secret
     (public-key h)  (sign h msg)       (lookup kid)  (handle kid)  (handles)
     (register-public-key! pub)         → adds a peer's key to the public side
     (import-password! pw {:uses n})    → a password handle (one use by default)
     (default-signing-key) (set-default-signing-key! h) (ensure-default-signing-key!)

   Providers hold the secret material and run the operations on it (sign,
   DH, HKDF, AEAD, Argon2id, wrap: the Provider protocol, docs/12 phase 0);
   signet's crypto code never holds a key's material. Software providers
   (:memory, :sodium) are built with lending-provider, which runs each
   operation on material lent for that call only; a provider that cannot
   lend (hardware, an agent) implements the operations itself. :memory
   keeps material on the Clojure heap, inside the vault only, and wipes each
   lent copy after use."
  (:require [signet.encoding :as enc]
            [signet.key :as key]
            #?(:clj [signet.impl :as impl])))

;; ============================================================
;; Handles
;; ============================================================

(defrecord KeyHandle [type kid vault])

(defn handle?
  "Is x a key handle? Pure."
  [x]
  (instance? KeyHandle x))

(defn- ->handle
  "A KeyHandle for kid in vault-id. Pure."
  [vault-id kid]
  (->KeyHandle :signet/key-handle kid vault-id))

;; ============================================================
;; Providers
;; ============================================================

(defprotocol Provider
  "Holds secret key material and runs operations on it. An entry's material
   never leaves, except through -export. Secret results (a DH output, a
   derived key) are returned as material the caller owns (bytes, or a
   nacljc secret under :sodium): the caller adopts it into a vault or
   releases it with impl/destroy-material!. Public results (signatures,
   ciphertexts, plaintexts) are byte arrays. A provider that cannot run an
   operation throws."
  (-generate! [p alg] "Create a new key of alg (:ed25519 or :x25519) inside the provider. Returns its public key record.")
  (-import! [p alg secret-bytes] "Take a copy of secret-bytes as a key of alg. Returns its public key record.")
  (-generate-secret! [p kid alg n] "Create n random secret bytes inside the provider under kid, as alg (for symmetric keys).")
  (-adopt! [p kid alg material] "Take ownership of derived material (what the backend produced: bytes, or a nacljc secret) under kid.")
  (-has? [p kid] "Does this provider hold kid?")
  (-kids [p] "The kids this provider holds.")
  (-alg [p kid] "The algorithm of kid (:ed25519 or :x25519).")
  (-export [p kid] "A copy of kid's secret bytes.")
  (-destroy! [p kid] "Wipe and forget kid's material. Returns true if it held kid.")
  (-sign [p kid message] "Ed25519 signature (public) of message bytes with kid's seed.")
  (-x25519-dh [p kid their-pub] "X25519 shared secret of kid's key (X25519, or Ed25519 converted) and their X25519 public key bytes. Secret: the caller owns it.")
  (-hkdf [p kid as other info n] "HKDF-SHA-256, n bytes, with kid's material as the ikm (as :ikm; other is the salt, public bytes) or as the salt (as :salt; other is the ikm, material in hand). Secret: the caller owns it.")
  (-aead-encrypt [p kid nonce plaintext aad] "ChaCha20-Poly1305 of plaintext under kid's key: the ciphertext.")
  (-aead-decrypt [p kid nonce ciphertext aad] "Inverse of -aead-encrypt: the plaintext. Throws what the backend throws on authentication failure.")
  (-argon2id [p kid salt n limits] "Argon2id of kid's material (a password) with salt and limits, n bytes. Secret: the caller owns it.")
  (-wrap [p kid wrapping-key nonce aad] "kid's material encrypted (impl/wrap-material) under wrapping-key, material in hand: public bytes."))

(defprotocol Lending
  "INTERNAL: how a software provider holds material, for lending-provider,
   which builds every Provider operation from it. signet's crypto code
   calls the operations only; with-material (white-box tests) is the one
   caller."
  (-with-material [p kid f] "Call (f material) and return its result. material is valid only during f."))

#?(:cljs
   (defn- throw-cljs
     "Never returns. Throws: not yet implemented for ClojureScript."
     []
     (throw (js/Error. "signet.vault not yet implemented for ClojureScript"))))

(defn lending-provider
  "A Provider (and Lending) over storage functions, given as a map of
     :generate! :import! :generate-secret! :adopt! :has? :kids :alg :export
     :destroy!   the Provider methods of the same name, without p
     :with-material (fn [kid f]): call (f material), material valid only
                 during f
   Each operation runs signet's backend on material lent for that call
   only, so a software provider implements storage and gets the operations.
   Pure: returns a provider over the given functions' state."
  [{:keys [generate! import! generate-secret! adopt! has? kids alg export destroy! with-material]}]
  (reify
    Provider
    (-generate! [_ a] (generate! a))
    (-import! [_ a secret-bytes] (import! a secret-bytes))
    (-generate-secret! [_ kid a n] (generate-secret! kid a n))
    (-adopt! [_ kid a material] (adopt! kid a material))
    (-has? [_ kid] (has? kid))
    (-kids [_] (kids))
    (-alg [_ kid] (alg kid))
    (-export [_ kid] (export kid))
    (-destroy! [_ kid] (destroy! kid))
    (-sign [_ kid message]
      #?(:clj (with-material kid #(impl/ed25519-sign % message)) :cljs (throw-cljs)))
    (-x25519-dh [_ kid their-pub]
      #?(:clj  (let [a (alg kid)]
                 (with-material
                   kid (fn [m]
                         (case a
                           :x25519  (impl/x25519-dh m their-pub)
                           :ed25519 (let [xsk (impl/ed25519-seed->x25519-private m)]
                                      (try (impl/x25519-dh xsk their-pub)
                                           (finally (impl/destroy-material! xsk))))
                           (throw (ex-info "x25519-dh needs an X25519 or Ed25519 key"
                                           {:type ::wrong-algorithm :kid kid :algorithm a}))))))
         :cljs (throw-cljs)))
    (-hkdf [_ kid as other info n]
      #?(:clj  (with-material kid #(case as
                                     :ikm  (impl/hkdf-sha-256 % other info n)
                                     :salt (impl/hkdf-sha-256 other % info n)))
         :cljs (throw-cljs)))
    (-aead-encrypt [_ kid nonce plaintext aad]
      #?(:clj (with-material kid #(impl/chacha20-poly1305-encrypt % nonce plaintext aad)) :cljs (throw-cljs)))
    (-aead-decrypt [_ kid nonce ciphertext aad]
      #?(:clj (with-material kid #(impl/chacha20-poly1305-decrypt % nonce ciphertext aad)) :cljs (throw-cljs)))
    (-argon2id [_ kid salt n limits]
      #?(:clj (with-material kid #(impl/argon2id % salt n limits)) :cljs (throw-cljs)))
    (-wrap [_ kid wrapping-key nonce aad]
      #?(:clj (with-material kid #(impl/wrap-material wrapping-key nonce % aad)) :cljs (throw-cljs)))
    Lending
    (-with-material [_ kid f] (with-material kid f))))

#?(:clj
   (defn- wipe!
     "Overwrite bs with zeros. Impure: writes bs."
     [^bytes bs] (when bs (java.util.Arrays/fill bs (byte 0)))))

(defn ^:no-doc nacljc-secret?
  "INTERNAL: is x a nacljc secret? Only possible on the libsodium backend.
   Pure."
  [x]
  #?(:clj  (and (= :sodium impl/backend) (boolean ((requiring-resolve 'nacljc.core/secret?) x)))
     :cljs false))

(defn ^:no-doc password-material?
  "INTERNAL: is x password material: a byte array (the UTF-8 of what was
   typed) or a nacljc secret (for example from nacljc.tty/read-password)?
   Pure."
  [x]
  (or #?(:clj (bytes? x) :cljs false) (nacljc-secret? x)))

(defn- as-bytes
  "Material as a byte array, for the :memory provider (which keeps keys on
   the heap by design): bytes as they are; a nacljc secret exported, then
   destroyed. Impure: reads and destroys a secret."
  [m]
  #?(:clj  (if (nacljc-secret? m)
             (try ((requiring-resolve 'nacljc.core/secret-export) m {:i-understand :exposes-secret})
                  (finally (impl/destroy-material! m)))
             m)
     :cljs m))

(defn- copy-bytes
  "A copy of bs (on JS the array itself). Pure."
  [^bytes bs] #?(:clj (java.util.Arrays/copyOf bs (alength bs)) :cljs bs))

(defn- public-key-record
  "The public key record for an Ed25519 seed or an X25519 secret key (bytes,
   or whatever the backend accepts in their place).
   Pure for byte material; with a nacljc secret, impure: reads it."
  [alg material]
  #?(:clj  (case alg
             :ed25519 (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519
                                              (impl/ed25519-seed->public-key material))
             :x25519  (key/->X25519PublicKey :signet/x25519-public-key :X25519
                                             (impl/x25519-private->public-key material)))
     :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript"))))

(defn memory-provider
  "A provider that keeps secrets on the Clojure heap, inside the vault only.
   Each operation gets a copy, wiped as soon as it returns. Destroying a key
   wipes the stored bytes. Impure: returns a new, empty provider (its
   state is mutable)."
  []
  (let [secrets (atom {})
        store!  (fn [alg ^bytes material]
                  (let [pub (public-key-record alg material)]
                    (swap! secrets assoc (key/kid pub) {:alg alg :material (copy-bytes material)})
                    pub))]
    (lending-provider
     {:generate!
      (fn [alg]
        ;; The backend's keypair generators, not seed -> public-key: the JCA
        ;; backend cannot derive a public key from a seed on babashka.
        #?(:clj  (let [[x m] (case alg
                               :ed25519 (impl/generate-ed25519-keypair)
                               :x25519  (impl/generate-x25519-keypair))
                       pub (case alg
                             :ed25519 (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 x)
                             :x25519  (key/->X25519PublicKey :signet/x25519-public-key :X25519 x))]
                   (try (swap! secrets assoc (key/kid pub) {:alg alg :material (copy-bytes m)})
                        pub
                        (finally (wipe! m))))
           :cljs (throw-cljs)))
      :import! store!
      :generate-secret!
      (fn [kid alg n]
        #?(:clj  (swap! secrets assoc kid {:alg alg :material (impl/random-bytes n)})
           :cljs (throw-cljs))
        nil)
      :adopt! (fn [kid alg material] (swap! secrets assoc kid {:alg alg :material (as-bytes material)}) nil)
      :has? (fn [kid] (contains? @secrets kid))
      :kids (fn [] (set (keys @secrets)))
      :alg (fn [kid] (:alg (get @secrets kid)))
      :with-material
      (fn [kid f]
        (let [m (copy-bytes (:material (get @secrets kid)))]
          (try (f m)
               (finally #?(:clj (wipe! m))))))
      :export (fn [kid] (copy-bytes (:material (get @secrets kid))))
      :destroy!
      (fn [kid]
        (let [[old _] (swap-vals! secrets dissoc kid)]
          (when-let [m (get-in old [kid :material])]
            #?(:clj (wipe! m))
            true)))})))

(defn default-provider
  "The provider a vault gets when none is given: :sodium (secrets in
   libsodium's guarded memory, via nacljc) when signet runs on the libsodium
   backend, else :memory. Impure: returns a new provider."
  []
  #?(:clj  (if (= :sodium impl/backend)
             ((requiring-resolve 'signet.vault.sodium/sodium-provider))
             (memory-provider))
     :cljs (memory-provider)))

;; ============================================================
;; Vault registry
;; ============================================================

(defonce ^:private vaults (atom {}))

;; The gate: a read/write lock per vault (docs/11). Operations that lend
;; material hold the read side, so they run in parallel; destroying an
;; entry takes the write side, so it waits for the operations in flight
;; and no new one starts meanwhile. Without it, a destroy racing an
;; operation freed a key under the operation's feet, or (under :sodium,
;; where nacljc refuses to free a secret in use) failed. A fair Semaphore
;; (bb has no ReadWriteLock): a read takes one permit, a write all of
;; them. *held* (thread-local) makes both reentrant, and turns a destroy
;; from inside an operation, which would wait for itself, into an error.

(def ^:private gate-permits 65536)

(def ^:private ^:dynamic *held*
  "The gates this thread holds: gate -> :read or :write."
  {})

(defn- new-gate
  "A new gate. Impure: returns a new lock."
  []
  #?(:clj (java.util.concurrent.Semaphore. gate-permits true) :cljs nil))

(defn- with-read
  "Call (f) holding vault v's gate for reading. Impure: takes the lock."
  [v f]
  #?(:clj  (let [^java.util.concurrent.Semaphore g (:gate v)]
             (if (get *held* g)
               (f)
               (do (.acquire g)
                   (try (binding [*held* (assoc *held* g :read)] (f))
                        (finally (.release g))))))
     :cljs (f)))

(defn- with-write
  "Call (f) holding vault v's gate for writing: after every operation in
   flight has returned. Impure: takes the lock.
   Throws ex-info {:type ::destroy-inside-operation} when this thread is
   inside an operation on v (waiting would deadlock)."
  [v f]
  #?(:clj  (let [^java.util.concurrent.Semaphore g (:gate v)]
             (case (get *held* g)
               :write (f)
               :read  (throw (ex-info "Cannot destroy a vault entry from inside an operation on the same vault"
                                      {:type ::destroy-inside-operation :vault (:id v)}))
               (do (.acquire g (int gate-permits))
                   (try (binding [*held* (assoc *held* g :write)] (f))
                        (finally (.release g (int gate-permits)))))))
     :cljs (f)))

(defn register-vault!
  "Register vault id with provider (default: default-provider). Returns id.
   Impure: writes the vault registry. Throws ex-info {:type ::vault-exists}
   if id is already registered."
  ([id] (register-vault! id (default-provider)))
  ([id provider]
   (let [v {:id id :provider provider :public (atom {}) :defaults (atom {}) :shared (atom {})
            ;; session entries (signet.session's secrets): entry id -> session id
            :session (atom {})
            ;; the vault's own secrets (a vault file's master key): entry ids
            :internal (atom #{})
            ;; a vault file's state (signet.vault.file), or nil
            :file (atom nil)
            :gate (new-gate)}
         [old _] (swap-vals! vaults (fn [m] (if (contains? m id) m (assoc m id v))))]
     (when (contains? old id)
       (throw (ex-info (str "Vault " id " is already registered") {:type ::vault-exists :vault id})))
     id)))

(defn unregister-vault!
  "Remove vault id from the registry, destroying every secret it holds.
   Impure: writes the registry and the provider. Returns nil."
  [id]
  (when-let [v (get @vaults id)]
    (with-write v #(doseq [kid (-kids (:provider v))]
                     (-destroy! (:provider v) kid)))
    (swap! vaults dissoc id))
  nil)

(defn vault-ids
  "The registered vault ids. Impure: reads the registry."
  []
  (set (keys @vaults)))

(defn- vault
  "The vault named id. Throws ::unknown-vault, never falls back.
   Impure: reads the vault registry."
  [id]
  (or (get @vaults id)
      (throw (ex-info (str "Unknown vault " (pr-str id)) {:type ::unknown-vault :vault id}))))

(defn- session-entry?
  "Is kid a session entry of vault v? Impure: reads the vault."
  [v kid] (contains? @(:session v) kid))

(defn- hidden?
  "Is kid a session entry or one of the vault's own secrets? Such entries
   never get a handle. Impure: reads the vault."
  [v kid] (or (session-entry? v kid) (contains? @(:internal v) kid)))

(defn- locked?*
  "Is vault v a locked vault file? Impure: reads the vault."
  [v] (boolean (:locked? @(:file v))))

(defn- throw-locked
  "Never returns. Throws ex-info {:type ::vault-locked}."
  [v]
  (throw (ex-info (str "Vault " (pr-str (:id v)) " is locked: unlock it first")
                  {:type ::vault-locked :vault (:id v)})))

(defn- note-use!
  "A key use or a write on vault v: runs its file's :on-use (auto-lock:
   lock when due, else record the activity). Skipped inside an operation
   on v, which noted the use already (and must not lock under itself).
   Impure: whatever :on-use does (it may lock the vault)."
  [v]
  (when-not (get *held* (:gate v))
    (when-let [on-use (:on-use @(:file v))] (on-use))))

(defn- unlocked
  "The vault named id, for a write: throws when it is a locked vault file.
   Notes the use (auto-lock). Impure: reads the vault registry, notes a
   use. Throws ex-info {:type ::unknown-vault} or {:type ::vault-locked}."
  [id]
  (let [v (vault id)]
    (note-use! v)
    (when (locked?* v) (throw-locked v))
    v))

(defn- changed!
  "Note a change to what a vault file saves (identity keys, the public
   side, the default): marks the file dirty and runs its :on-change (the
   auto-save). Impure: writes the vault's file state, and whatever
   :on-change writes."
  [vault-id]
  (let [f (:file (vault vault-id))]
    (when @f
      (swap! f assoc :dirty? true)
      (when-let [on-change (:on-change @f)] (on-change)))))

(when-not (contains? @vaults :default)
  (register-vault! :default))

(defn reset-default-vault!
  "Destroy every secret in the :default vault and start it empty with a new
   default-provider. For tests and REPL sessions. Impure."
  []
  (unregister-vault! :default)
  (register-vault! :default)
  nil)

;; ============================================================
;; Two sides: public (lookup) and secret (handle)
;; ============================================================

(defn register-public-key!
  "Put public key pub on vault's public side (default :default). Returns
   its kid. Keys enter the public side only through this function (or
   through generation and import). Impure: writes the public side.
   Throws ex-info {:type ::bad-key-type} unless pub is a key record."
  ([pub] (register-public-key! :default pub))
  ([vault-id pub]
   (unlocked vault-id)
   (let [pub (try (key/public-key pub)
                  (catch IllegalArgumentException _
                    (throw (ex-info "register-public-key! needs a key record"
                                    {:type ::bad-key-type :got (str (type pub))}))))
         kid (key/kid pub)]
     (swap! (:public (vault vault-id)) assoc kid pub)
     (changed! vault-id)
     kid)))

(defn lookup
  "The public key for kid: from vault's public side (default :default),
   else parsed from the kid itself (25519 kids contain their key), else nil.
   Impure: reads the public side. Never throws for a malformed kid."
  ([kid] (lookup :default kid))
  ([vault-id kid]
   (or (get @(:public (vault vault-id)) kid)
       (key/lookup kid))))

(defn handle
  "A handle for kid if vault's secret side (default :default) holds its
   private key, else nil. Never a session's internal secret.
   Impure: reads the vault."
  ([kid] (handle :default kid))
  ([vault-id kid]
   (let [v (vault vault-id)]
     (when (and (-has? (:provider v) kid) (not (hidden? v kid)))
       (->handle vault-id kid)))))

(defn handles
  "Handles for every key vault's secret side (default :default) holds,
   except sessions' internal secrets. Impure: reads the vault."
  ([] (handles :default))
  ([vault-id]
   (let [v (vault vault-id)]
     (set (map #(->handle vault-id %)
               (remove #(hidden? v %) (-kids (:provider v))))))))

(defn- check-handle
  "h, if it is a KeyHandle; throws otherwise. Pure.
   Throws ex-info {:type ::not-a-handle} for anything else."
  [h what]
  (when-not (handle? h)
    (throw (ex-info (str what " needs a key handle")
                    {:type ::not-a-handle :got (str (type h))})))
  h)

(defn- provider-of
  "The provider holding h's key. Throws ::unknown-vault, or
   ::destroyed-key when the vault does not hold it (never held, or
   destroyed).
   Impure: reads the vault."
  [h]
  (let [v (vault (:vault h))
        p (:provider v)]
    (when (and (not (-has? p (:kid h))) (locked?* v))
      (throw-locked v))
    (when-not (-has? p (:kid h))
      (throw (ex-info "The vault does not hold this key (destroyed, or never held)"
                      {:type ::destroyed-key :kid (:kid h) :vault (:vault h)})))
    p))

(defn ^:no-doc with-material
  "INTERNAL, for white-box tests: call (f material) with h's secret
   material and return f's result. material is valid only during f.
   signet's crypto code never calls this: it runs operations (run-op).
   Impure: reads the vault.
   Throws ex-info {:type ::not-lending} when h's provider does not lend
   (it implements the operations only), and what provider-of throws."
  [h f]
  (check-handle h "with-material")
  (let [v (vault (:vault h))]
    (note-use! v)
    (with-read v #(let [p (provider-of h)]
                    (when-not (satisfies? Lending p)
                      (throw (ex-info "This vault's provider does not lend material"
                                      {:type ::not-lending :vault (:vault h)})))
                    (-with-material p (:kid h) f)))))

(defn- run-op
  "(f provider kid) for h's key, holding its vault's gate for reading, after
   noting the use (auto-lock). Impure: reads the vault, and what f does.
   Throws ::not-a-handle, and what provider-of and f throw."
  [h what f]
  (check-handle h what)
  (let [v (vault (:vault h))]
    (note-use! v)
    (with-read v #(f (provider-of h) (:kid h)))))

;; ============================================================
;; Keys are born in the vault
;; ============================================================

(defn- add-key!
  "Record a key the provider now holds: its public key on the public side.
   Returns its handle.
   Impure: writes the vault's public side."
  [vault-id pub]
  (let [kid (key/kid pub)]
    (swap! (:public (vault vault-id)) assoc kid pub)
    (changed! vault-id)
    (->handle vault-id kid)))

(defn generate-signing-key!
  "Create a new Ed25519 signing key inside vault (default :default) and
   return its handle. The seed is born in the provider and never leaves it
   (under :sodium it never touches the Clojure heap).
   Impure: draws from the CSPRNG and writes the vault."
  ([] (generate-signing-key! :default))
  ([vault-id]
   (add-key! vault-id (-generate! (:provider (unlocked vault-id)) :ed25519))))

(defn generate-encryption-key!
  "Create a new X25519 encryption key inside vault (default :default) and
   return its handle. Impure: draws from the CSPRNG and writes the vault."
  ([] (generate-encryption-key! :default))
  ([vault-id]
   (add-key! vault-id (-generate! (:provider (unlocked vault-id)) :x25519))))

(defn- check-secret-bytes
  "Throws unless x is a 32-byte array. Pure.
   Throws ex-info {:type ::bad-secret} otherwise."
  [x what]
  (when-not (and #?(:clj (bytes? x) :cljs false) (= 32 (alength ^bytes x)))
    (throw (ex-info (str what " must be 32 bytes")
                    {:type ::bad-secret :what what :got (str (type x))}))))

(defn- import-key!
  "Import secret-bytes as a key of alg into vault-id; returns its handle.
   Impure: writes the vault and wipes secret-bytes (also on failure).
   Throws what the provider and the vault throw."
  [vault-id alg secret-bytes]
  (try
    (add-key! vault-id (-import! (:provider (unlocked vault-id)) alg secret-bytes))
    (finally #?(:clj (wipe! secret-bytes)))))

(defn import-signing-key!
  "Import an Ed25519 seed (32 bytes) into vault (default :default) and
   return its handle. HANDLE WITH CARE: this is how secret bytes enter a
   vault (key files, backups, SSH keys: (import-signing-key! (:d kp))). The
   caller's array is wiped afterwards. On babashka this needs the
   libsodium backend (the JCA backend cannot derive a public key from a
   seed there).
   Impure: writes the vault and the seed array.
   Throws ex-info {:type ::bad-secret} unless seed is 32 bytes."
  ([seed] (import-signing-key! :default seed))
  ([vault-id seed]
   (check-secret-bytes seed "Ed25519 seed")
   (import-key! vault-id :ed25519 seed)))

(defn import-encryption-key!
  "Import an X25519 secret key (32 bytes) into vault (default :default) and
   return its handle. HANDLE WITH CARE, as import-signing-key!. The
   caller's array is wiped afterwards.
   Impure: writes the vault and the key array.
   Throws ex-info {:type ::bad-secret} unless sk is 32 bytes."
  ([sk] (import-encryption-key! :default sk))
  ([vault-id sk]
   (check-secret-bytes sk "X25519 secret key")
   (import-key! vault-id :x25519 sk)))

(def ^:private export-acknowledgement {:i-understand :exposes-secret})

(defn export-secret
  "The secret bytes of h's key: the Ed25519 seed or the X25519 secret key.
   This is the only way secret bytes leave a vault, so it requires the
   acknowledgement {:i-understand :exposes-secret}. Wipe the result when
   done. Impure: reads the vault.
   Throws ex-info {:type ::export-not-acknowledged} without it, and
   ::not-a-handle, ::unknown-vault, ::destroyed-key, or ::not-exportable
   for a session's internal secret."
  [h ack]
  (check-handle h "export-secret")
  (when-not (= export-acknowledgement ack)
    (throw (ex-info "export-secret needs {:i-understand :exposes-secret}"
                    {:type ::export-not-acknowledged})))
  (when (hidden? (vault (:vault h)) (:kid h))
    (throw (ex-info "A session's or the vault's internal secret cannot be exported"
                    {:type ::not-exportable :kid (:kid h)})))
  (let [v (vault (:vault h))]
    (note-use! v)
    (with-read v #(-export (provider-of h) (:kid h)))))

(defn destroy!
  "Wipe and remove h's secret from its vault. The public key stays on the
   public side. Later use of h throws ::destroyed-key; destroying again is
   a no-op. Impure: writes the vault. Returns nil."
  [h]
  (check-handle h "destroy!")
  (let [v        (vault (:vault h))
        saved?   (and (not (hidden? v (:kid h)))
                      (#{:ed25519 :x25519} (-alg (:provider v) (:kid h))))
        existed? (with-write v #(-destroy! (:provider v) (:kid h)))]
    (swap! (:session v) dissoc (:kid h))
    (swap! (:defaults v) (fn [d] (into {} (remove (fn [[_ x]] (= x h)) d))))
    (when (and existed? saved?) (changed! (:vault h))))
  nil)

(defn ^:no-doc adopt-symmetric!
  "INTERNAL to signet.shared and signet.password: store derived symmetric
   material (bytes or a nacljc secret; the vault takes ownership) under kid
   in vault-id as a key of kind (:shared or :password), with its public
   metadata (which records the kind). If the vault already holds kid, the
   new material is released instead (the same inputs derive the same key).
   Returns the handle. Impure: writes the vault."
  [vault-id kid kind material meta]
  (let [v (try (unlocked vault-id)
               (catch #?(:clj Throwable :cljs :default) t
                 #?(:clj (impl/destroy-material! material)) (throw t)))]
    (if (-has? (:provider v) kid)
      #?(:clj (impl/destroy-material! material) :cljs nil)
      (-adopt! (:provider v) kid kind material))
    (swap! (:shared v) assoc kid (assoc meta :kind kind))
    (->handle vault-id kid)))

(defn ^:no-doc adopt-shared!
  "INTERNAL to signet.shared: adopt-symmetric! as a :shared key.
   Impure: writes the vault."
  [vault-id kid material meta]
  (adopt-symmetric! vault-id kid :shared material meta))

(defn ^:no-doc shared-meta
  "INTERNAL to signet.shared: the public metadata of shared key h, or nil.
   Impure: reads the vault.
   Throws ex-info {:type ::unknown-vault} for an unknown vault."
  [h]
  (get @(:shared (vault (:vault h))) (:kid h)))

(defn public-key
  "The public key record of h's key, or nil if the vault does not know it.
   Impure: reads the vault's public side.
   Throws ex-info {:type ::wrong-algorithm} for a shared key (it has no
   public key), and ::not-a-handle or ::unknown-vault."
  [h]
  (check-handle h "public-key")
  (let [v (vault (:vault h))]
    (when (contains? @(:shared v) (:kid h))
      (throw (ex-info "A shared key has no public key"
                      {:type ::wrong-algorithm :kid (:kid h) :algorithm :shared})))
    (or (get @(:public v) (:kid h))
        (key/lookup (:kid h)))))

(defn algorithm
  "h's algorithm: :ed25519 or :x25519 for an identity key, :shared for a
   shared key, :session or :x25519 for a session's secret.
   Impure: reads the vault."
  [h]
  (check-handle h "algorithm")
  (-alg (provider-of h) (:kid h)))

;; ============================================================
;; Operations
;; ============================================================

(def ^:private identity-algorithms
  "The kinds of key that are an identity: they have a public key and take
   part in signing or key agreement. Shared keys (:shared) and session
   secrets are not."
  #{:ed25519 :x25519})

(defn identity-key?
  "Does h name an identity key (Ed25519 or X25519) that its vault holds?
   False for shared keys, session secrets and keys it does not hold.
   Impure: reads the vault. Throws ex-info {:type ::not-a-handle} for
   anything but a handle, and {:type ::unknown-vault} for an unknown vault."
  [h]
  (check-handle h "identity-key?")
  (let [p (:provider (vault (:vault h)))]
    (boolean (and (-has? p (:kid h)) (identity-algorithms (-alg p (:kid h)))))))

(defn ^:no-doc check-identity
  "INTERNAL to signet: h, if its vault holds it as an identity key; throws
   otherwise.
   Impure: reads the vault.
   Throws ex-info {:type ::wrong-algorithm} for a shared key or a session
   secret, and what provider-of throws."
  [h what]
  (let [p (provider-of h)]
    (when-not (identity-algorithms (-alg p (:kid h)))
      (throw (ex-info (str what " needs an Ed25519 or X25519 key, not a " (name (-alg p (:kid h))) " key")
                      {:type ::wrong-algorithm :kid (:kid h) :algorithm (-alg p (:kid h))})))
    h))

(defn ^:no-doc x25519-dh
  "INTERNAL to signet's crypto code (box, shared keys): the X25519 shared
   secret of h's key (X25519, or Ed25519 converted inside the call) and
   their X25519 public key bytes: a byte array, or under the :sodium
   provider a nacljc secret. The caller must release it with
   impl/destroy-material! as soon as it is consumed. Impure: reads the vault.
   Throws ::not-a-handle, ::unknown-vault, ::destroyed-key, or
   ::wrong-algorithm for a shared key or a session secret."
  [h their-x25519-pub]
  (check-handle h "x25519-dh")
  (when-not (session-entry? (vault (:vault h)) (:kid h)) ; ephemerals are X25519 session entries
    (check-identity h "x25519-dh"))
  (run-op h "x25519-dh" (fn [p kid] (-x25519-dh p kid their-x25519-pub))))

(defn sign
  "Ed25519 signature (64 bytes) of message bytes with h's key. The seed is
   lent to the signing call only. Impure: reads the vault.
   Throws ::not-a-handle, ::unknown-vault, ::destroyed-key, or
   ::wrong-algorithm for a non-signing key."
  [h message-bytes]
  (run-op h "sign" (fn [p kid]
                     (when-not (= :ed25519 (-alg p kid))
                       (throw (ex-info "sign needs an Ed25519 signing key" {:type ::wrong-algorithm :kid kid})))
                     (-sign p kid message-bytes))))

(defn ^:no-doc hkdf-material
  "INTERNAL to signet.shared and signet.password: HKDF-SHA-256 (n bytes)
   with h's key as the ikm, run inside its provider. Returns material
   (bytes, or a nacljc secret under :sodium) that the caller must release
   with impl/destroy-material!. Impure: reads the vault.
   Throws ::not-a-handle, ::unknown-vault, ::destroyed-key."
  [h salt info n]
  (run-op h "hkdf-material" (fn [p kid] (-hkdf p kid :ikm salt info n))))

;; ============================================================
;; Session entries: signet.session's secrets (docs/08)
;;
;; The chaining key, handshake key, transport keys and ephemerals of a
;; Noise session live on the secret side as session entries, tagged with
;; their session's id. They never go on the public side, never appear in
;; handle/handles, cannot be exported, and are destroyed together by
;; destroy-session!. The functions below are INTERNAL to signet.session,
;; except session-entry-count (monitoring).
;; ============================================================

(defn- new-entry-id
  "A random session-entry id, urn:signet:session:<base64url>. Impure:
   draws from the CSPRNG."
  []
  #?(:clj  (str "urn:signet:session:" (enc/bytes->base64url (impl/random-bytes 16)))
     :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript"))))

(defn- with-temp-entry
  "Adopt bs (a byte array, or a nacljc secret) into vault-id's provider as
   a temporary entry (under :sodium an array moves into guarded memory and
   is wiped at once; a secret is taken as it is), call (f provider entry-id)
   and return its result, then destroy the entry. So bs is consumed: wiped,
   or destroyed, also when the vault is unknown. Works on a locked vault
   too (unlocking needs it); nothing lasting is written.
   Impure: writes and reads the vault's provider, consumes bs.
   Throws ex-info {:type ::unknown-vault}, and what f throws."
  [vault-id bs f]
  (let [p   (try (:provider (vault vault-id))
                 (catch #?(:clj Throwable :cljs :default) t
                   #?(:clj (impl/destroy-material! bs)) (throw t)))
        tmp (new-entry-id)]
    (-adopt! p tmp :temporary bs)
    ;; the gate covers the operation; the destroy needs none: no other
    ;; thread knows this entry (and clear! waits for the operation)
    (try (with-read (vault vault-id) #(f p tmp))
         (finally (-destroy! p tmp)))))

(defn ^:no-doc temp-hkdf
  "INTERNAL to signet.vault.file: HKDF-SHA-256 (n bytes) with bs as the
   ikm, run inside vault-id's provider on a temporary entry (see
   with-temp-entry: bs is consumed). Returns material the caller must
   release with impl/destroy-material!. Works on a locked vault.
   Impure: writes and reads the vault's provider, consumes bs.
   Throws ex-info {:type ::unknown-vault}."
  [vault-id bs salt info n]
  (with-temp-entry vault-id bs (fn [p tmp] (-hkdf p tmp :ikm salt info n))))

(defn- claim-password-use!
  "Take one use of password handle h: :last when it was the last (the
   caller destroys the entry after using it), :more, or :keep (unlimited).
   Atomic, so concurrent callers never share the last use.
   Impure: writes the vault's metadata.
   Throws ex-info {:type ::destroyed-key} when no use is left."
  [h]
  (let [v   (vault (:vault h))
        kid (:kid h)
        [old _] (swap-vals! (:shared v)
                            (fn [m] (let [u (get-in m [kid :uses])]
                                      (if (and u (pos? u)) (assoc-in m [kid :uses] (dec u)) m))))
        u   (get-in old [kid :uses] ::none)]
    (cond
      (nil? u)                   :keep
      (and (number? u) (> u 1))  :more
      (= 1 u)                    :last
      :else (throw (ex-info "This password handle has no use left (destroyed, or used up)"
                            {:type ::destroyed-key :kid kid :vault (:vault h)})))))

(defn ^:no-doc password-handle?
  "INTERNAL: is x a handle made by import-password!? Impure: reads the
   vault. Never throws (an unknown vault gives false)."
  [x]
  (boolean (and (handle? x)
                (try (= :password-input (:kind (get @(:shared (vault (:vault x))) (:kid x))))
                     (catch #?(:clj Throwable :cljs :default) _ false)))))

(defn ^:no-doc password-input?
  "INTERNAL to signet.password and signet.vault.file: can x be given as a
   password: a byte array, a nacljc secret, or a password handle
   (import-password!)? Impure: reads the vault for a handle."
  [x]
  (or (password-material? x) (password-handle? x)))

(defn import-password!
  "Move a password into vault (default :default) and return a handle to
   it: every function that takes a password also takes this handle, so
   code can pass the password on without holding its bytes (ask once,
   unlock several vaults). password is a byte array (the UTF-8 of what was
   typed) or a nacljc secret (nacljc.tty/read-password); it is consumed.

   One use by default: the entry is destroyed after its first use.
     {:uses n}     n uses
     {:keep true}  until destroy! or the vault locks
   A kept password can unlock a vault again without the user, which undoes
   auto-lock: keep it only as long as needed. lock! destroys it.

   Impure: writes the vault, consumes password.
   Throws ex-info {:type ::bad-password} unless password is bytes or a
   secret, {:type ::bad-option} for bad options, ::unknown-vault and
   ::vault-locked (the password is consumed either way)."
  ([password] (import-password! :default password nil))
  ([vault-id password] (import-password! vault-id password nil))
  ([vault-id password {:keys [uses keep] :as opts}]
   (try
     (when-not (password-material? password)
       (throw (ex-info "import-password!: the password must be a byte array or a nacljc secret"
                       {:type ::bad-password :got (str (type password))})))
     (when (or (and (contains? opts :uses) (not (pos-int? uses)))
               (and keep (contains? opts :uses))
               (not (contains? #{nil true false} keep)))
       (throw (ex-info "import-password!: {:uses n} (n > 0) or {:keep true}" {:type ::bad-option})))
     (let [v   (unlocked vault-id)
           kid #?(:clj  (str "urn:signet:password-input:" (enc/bytes->base64url (impl/random-bytes 16)))
                  :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript")))]
       (-adopt! (:provider v) kid :password-input password)
       (swap! (:shared v) assoc kid {:kind :password-input :uses (when-not keep (or uses 1))})
       (->handle vault-id kid))
     (catch #?(:clj Throwable :cljs :default) t
       #?(:clj (impl/destroy-material! password))
       (throw t)))))

(defn ^:no-doc argon2id-material
  "INTERNAL to signet.password and signet.vault.file: Argon2id of password
   with salt and limits, run inside a vault's provider. password is a byte
   array or a nacljc secret, which becomes a temporary entry of vault-id
   (under :sodium in guarded memory) and is consumed; or a password handle
   (import-password!), used inside its own vault, one use taken (the entry
   is destroyed after its last). Returns 32 bytes of material (bytes, or a
   nacljc secret under :sodium) that the caller must adopt or destroy.
   Impure: writes and reads the providers, consumes password.
   Throws what impl/argon2id throws (:signet.impl/unsupported on the JCA
   backend), and ::destroyed-key for a used-up handle."
  [vault-id password salt limits]
  (let [f (fn [p kid] (-argon2id p kid salt 32 limits))]
    (if (handle? password)
      (let [claim (claim-password-use! password)]
        (try (run-op password "argon2id-material" f)
             (finally (when (= :last claim) (destroy! password)))))
      (with-temp-entry vault-id password f))))

(defn- adopt-session-entry!
  "Store material (the vault takes ownership) as a new session entry of
   session-id. Returns its handle.
   Impure: writes the vault."
  [vault-id session-id alg material]
  (let [v  (unlocked vault-id)
        id (new-entry-id)]
    ;; the provider first: a refused adoption leaves no orphan tag
    (-adopt! (:provider v) id alg material)
    (swap! (:session v) assoc id session-id)
    (->handle vault-id id)))

(defn ^:no-doc generate-ephemeral!
  "INTERNAL to signet.session: a new X25519 key born in vault-id's provider
   (under :sodium, in guarded memory), as a session entry of session-id.
   Returns [handle public-key-bytes]. Its id is its public key's kid: the
   public key is sent in the clear anyway. Impure: draws from the CSPRNG
   and writes the vault."
  [vault-id session-id]
  (let [v   (unlocked vault-id)
        pub (-generate! (:provider v) :x25519)
        kid (key/kid pub)]
    (swap! (:session v) assoc kid session-id)
    [(->handle vault-id kid) (:x pub)]))

(defn ^:no-doc hkdf-pair!
  "INTERNAL to signet.session: Noise's HKDF (RFC 5869, empty info) with two
   32-byte outputs, kept in vault-id as two new session entries of
   session-id. salt is public bytes (the initial chaining key) or a
   handle; ikm is material (bytes, or a nacljc secret under :sodium),
   which this consumes and destroys. Returns [handle1 handle2].
   Impure: reads and writes the vault; destroys ikm."
  [vault-id session-id salt ikm]
  #?(:clj
     (try
       (let [out (if (handle? salt)
                   (run-op salt "hkdf-pair!" (fn [p kid] (-hkdf p kid :salt ikm (byte-array 0) 64)))
                   (impl/hkdf-sha-256 ikm salt (byte-array 0) 64))]
         (try
           (let [[a b] (impl/split-material out [32 32])]
             [(adopt-session-entry! vault-id session-id :session a)
              (adopt-session-entry! vault-id session-id :session b)])
           (finally (impl/destroy-material! out))))
       (finally (impl/destroy-material! ikm)))
     :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript"))))

(defn ^:no-doc aead-encrypt
  "INTERNAL to signet.session: ChaCha20-Poly1305 of plaintext under h's key
   with the caller's nonce (12 bytes) and aad (nil for none). The caller
   owns nonce uniqueness. Impure: reads the vault."
  [h nonce plaintext aad]
  (run-op h "aead-encrypt" (fn [p kid] (-aead-encrypt p kid nonce plaintext aad))))

(defn ^:no-doc aead-decrypt
  "INTERNAL to signet.session: inverse of aead-encrypt. Throws whatever the
   backend throws on authentication failure (signet.session maps it to one
   error). Impure: reads the vault."
  [h nonce ciphertext aad]
  (run-op h "aead-decrypt" (fn [p kid] (-aead-decrypt p kid nonce ciphertext aad))))

(defn ^:no-doc destroy-session!
  "INTERNAL to signet.session: destroy every entry of session-id in
   vault-id. Destroying again is a no-op. Impure: writes the vault.
   Returns nil."
  [vault-id session-id]
  (let [v (vault vault-id)]
    (with-write v #(doseq [[id sid] @(:session v) :when (= sid session-id)]
                     (-destroy! (:provider v) id)
                     (swap! (:session v) dissoc id))))
  nil)

(defn session-entry-count
  "How many session entries (Noise session secrets) vault (default
   :default) holds. A session that is never closed leaves its entries
   behind: this is for monitoring. Impure: reads the vault."
  ([] (session-entry-count :default))
  ([vault-id] (count @(:session (vault vault-id)))))

;; ============================================================
;; Default identity (per vault)
;; ============================================================

(defn default-signing-key
  "The default signing key handle of vault (default :default), or nil.
   Impure: reads the vault."
  ([] (default-signing-key :default))
  ([vault-id] (:signing @(:defaults (vault vault-id)))))

(defn set-default-signing-key!
  "Make h the default signing key of its vault. Impure: writes the vault.
   Throws ::not-a-handle, ::destroyed-key or ::wrong-algorithm."
  [h]
  (check-handle h "set-default-signing-key!")
  (when-not (= :ed25519 (-alg (provider-of h) (:kid h)))
    (throw (ex-info "The default signing key must be an Ed25519 key"
                    {:type ::wrong-algorithm :kid (:kid h)})))
  (swap! (:defaults (vault (:vault h))) assoc :signing h)
  (changed! (:vault h))
  h)

(defn ensure-default-signing-key!
  "The default signing key of vault (default :default), generating one
   first if there is none. Under concurrency exactly one generated key
   becomes the default, and every caller gets it; the others are destroyed.
   Impure: may draw from the CSPRNG and write the vault."
  ([] (ensure-default-signing-key! :default))
  ([vault-id]
   (or (default-signing-key vault-id)
       (let [h        (generate-signing-key! vault-id)
             defaults (:defaults (vault vault-id))
             [old _]  (swap-vals! defaults (fn [d] (if (:signing d) d (assoc d :signing h))))]
         (if-let [winner (:signing old)]
           (do (destroy! h) winner)
           (do (changed! vault-id) h))))))

;; ============================================================
;; Vault files: INTERNAL to signet.vault.file
;;
;; A vault file saves the identity keys (each wrapped under a key derived
;; from the vault's master key), the public side and the default signing
;; key. The master key is one of the vault's own secrets: an internal
;; entry, never a handle, never exported. Shared keys, password keys and
;; session entries are not saved.
;; ============================================================

(defn ^:no-doc file-state
  "INTERNAL: the atom holding vault-id's file state (nil: no file).
   Impure: reads the vault registry.
   Throws ex-info {:type ::unknown-vault}."
  [vault-id]
  (:file (vault vault-id)))

(defn ^:no-doc blank?
  "INTERNAL: does vault-id hold nothing (no secrets, no public keys, no
   file)? Impure: reads the vault.
   Throws ex-info {:type ::unknown-vault}."
  [vault-id]
  (let [v (vault vault-id)]
    (and (empty? (-kids (:provider v))) (empty? @(:public v)) (nil? @(:file v)))))

(defn ^:no-doc generate-internal!
  "INTERNAL: n random secret bytes born in vault-id's provider (under
   :sodium, in guarded memory) as one of the vault's own secrets. Returns
   its entry id. Impure: draws from the CSPRNG and writes the vault."
  [vault-id n]
  (let [v  (vault vault-id)
        id (new-entry-id)]
    (-generate-secret! (:provider v) id :internal n)
    (swap! (:internal v) conj id)
    id))

(defn ^:no-doc adopt-internal!
  "INTERNAL: store material (the vault takes ownership) as one of
   vault-id's own secrets. Returns its entry id. Impure: writes the vault."
  [vault-id material]
  (let [v  (vault vault-id)
        id (new-entry-id)]
    (-adopt! (:provider v) id :internal material)
    (swap! (:internal v) conj id)
    id))

(defn- internal-op
  "(f provider id) for the vault's own secret id, holding the gate for
   reading. Impure: reads the vault, and what f does.
   Throws ex-info {:type ::vault-locked} when the vault does not hold it."
  [vault-id id f]
  (let [v (vault vault-id)]
    (with-read v (fn []
                   (when-not (and id (-has? (:provider v) id)) (throw-locked v))
                   (f (:provider v) id)))))

(defn ^:no-doc internal-hkdf
  "INTERNAL: HKDF-SHA-256 (n bytes) with the vault's own secret id as the
   ikm. Returns material the caller must release with
   impl/destroy-material!. Impure: reads the vault.
   Throws ex-info {:type ::vault-locked} when the vault does not hold it."
  [vault-id id salt info n]
  (internal-op vault-id id (fn [p id] (-hkdf p id :ikm salt info n))))

(defn ^:no-doc internal-wrap
  "INTERNAL: the vault's own secret id wrapped (impl/wrap-material) under
   wrapping-key (material in hand) with nonce and aad: public bytes.
   Impure: reads the vault.
   Throws ex-info {:type ::vault-locked} when the vault does not hold it."
  [vault-id id wrapping-key nonce aad]
  (internal-op vault-id id (fn [p id] (-wrap p id wrapping-key nonce aad))))

(defn ^:no-doc destroy-internal!
  "INTERNAL: destroy the vault's own secret id. Impure: writes the vault."
  [vault-id id]
  (let [v (vault vault-id)]
    (with-write v #(-destroy! (:provider v) id))
    (swap! (:internal v) disj id)
    nil))

(defn ^:no-doc snapshot
  "INTERNAL: what a vault file saves, as
     {:public [kid …] :secrets [{:kid :alg :wrapped} …] :default-signing kid}
   Each identity key is wrapped inside the provider with the parameters
   (wrap-params i kid alg) gives, {:key wrapping-key-material :nonce :aad};
   the result is stored as :wrapped. Impure: reads the vault."
  [vault-id wrap-params]
  (let [v    (vault vault-id)
        p    (:provider v)
        kids (sort (filter #(and (not (hidden? v %)) (#{:ed25519 :x25519} (-alg p %))) (-kids p)))]
    (with-read v (fn [] {:public          (vec (sort (keys @(:public v))))
                         :secrets         (vec (map-indexed (fn [i kid]
                                                              (let [alg (-alg p kid)]
                                                                {:kid kid :alg alg
                                                                 :wrapped (let [{k :key :keys [nonce aad]} (wrap-params i kid alg)]
                                                                            (-wrap p kid k nonce aad))}))
                                                            kids))
                         :default-signing (:kid (:signing @(:defaults v)))}))))

(defn ^:no-doc clear!
  "INTERNAL: destroy every secret vault-id holds (identity keys, shared
   and password keys, session entries, its own secrets) and empty its
   public side, defaults and metadata. The file state stays.
   Impure: writes the vault."
  [vault-id]
  (let [v (vault vault-id)]
    (with-write v #(doseq [kid (-kids (:provider v))] (-destroy! (:provider v) kid)))
    (reset! (:public v) {})
    (reset! (:defaults v) {})
    (reset! (:shared v) {})
    (reset! (:session v) {})
    (reset! (:internal v) #{})
    nil))

(defn ^:no-doc restore!
  "INTERNAL: load a snapshot into vault-id: the public side, each secret
   ((unwrap i entry) gives its material, which must derive its kid), and
   the default signing key. All or nothing: on any failure the vault is
   cleared (clear!). Does not mark the file changed.
   Impure: writes the vault.
   Throws ex-info {:type ::corrupt-entry} when a secret does not belong
   to its kid or a kid is malformed, and what unwrap throws."
  [vault-id {:keys [public secrets default-signing]} unwrap]
  (let [v (vault vault-id)
        p (:provider v)]
    (try
      (doseq [kid public]
        (swap! (:public v) assoc kid
               (try (key/kid->public-key kid)
                    (catch #?(:clj Throwable :cljs :default) _
                      (throw (ex-info "Vault file: a malformed kid" {:type ::corrupt-entry}))))))
      (doseq [[i {:keys [kid alg] :as entry}] (map-indexed vector secrets)]
        (let [m (unwrap i entry)]
          (when-not (and (#{:ed25519 :x25519} alg)
                         (= kid (try (key/kid (public-key-record alg m))
                                     (catch #?(:clj Throwable :cljs :default) _ nil))))
            #?(:clj (impl/destroy-material! m))
            (throw (ex-info "Vault file: a secret does not belong to its kid"
                            {:type ::corrupt-entry :kid kid})))
          (-adopt! p kid alg m)
          (swap! (:public v) assoc kid (public-key-record alg m))))
      (when default-signing
        (when-not (= :ed25519 (-alg p default-signing))
          (throw (ex-info "Vault file: the default signing key is not an Ed25519 key it holds"
                          {:type ::corrupt-entry :kid default-signing})))
        (swap! (:defaults v) assoc :signing (->handle vault-id default-signing)))
      nil
      (catch #?(:clj Throwable :cljs :default) t
        (clear! vault-id)
        (throw t)))))
