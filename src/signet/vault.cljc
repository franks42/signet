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
     (default-signing-key) (set-default-signing-key! h) (ensure-default-signing-key!)

   Providers hold the secret material and lend it to one operation at a
   time (see with-material); signet's crypto code never keeps it. :memory
   keeps it on the Clojure heap, inside the vault only, and wipes each lent
   copy after use."
  (:require [signet.key :as key]
            #?(:clj [signet.impl :as impl])))

;; ============================================================
;; Handles
;; ============================================================

(defrecord KeyHandle [type kid vault])

(defn handle?
  "Is x a key handle? Pure."
  [x]
  (instance? KeyHandle x))

(defn- ->handle [vault-id kid]
  (->KeyHandle :signet/key-handle kid vault-id))

;; ============================================================
;; Providers
;; ============================================================

(defprotocol Provider
  "Holds secret key material. Implementations never return it, except
   through -export."
  (-generate! [p alg] "Create a new key of alg (:ed25519 or :x25519) inside the provider. Returns its public key record.")
  (-import! [p alg secret-bytes] "Take a copy of secret-bytes as a key of alg. Returns its public key record.")
  (-adopt! [p kid alg material] "Take ownership of derived material (what the backend produced: bytes, or a nacljc secret) under kid.")
  (-has? [p kid] "Does this provider hold kid?")
  (-kids [p] "The kids this provider holds.")
  (-alg [p kid] "The algorithm of kid (:ed25519 or :x25519).")
  (-with-material [p kid f] "Call (f material) and return its result. material is valid only during f.")
  (-export [p kid] "A copy of kid's secret bytes.")
  (-destroy! [p kid] "Wipe and forget kid's material. Returns true if it held kid."))

#?(:clj
   (defn- wipe! [^bytes bs] (when bs (java.util.Arrays/fill bs (byte 0)))))

(defn- copy-bytes [^bytes bs] #?(:clj (java.util.Arrays/copyOf bs (alength bs)) :cljs bs))

(defn- public-key-record
  "The public key record for an Ed25519 seed or an X25519 secret key (bytes,
   or whatever the backend accepts in their place)."
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
    (reify Provider
      (-generate! [_ alg]
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
           :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript"))))
      (-import! [_ alg secret-bytes] (store! alg secret-bytes))
      (-adopt! [_ kid alg material] (swap! secrets assoc kid {:alg alg :material material}) nil)
      (-has? [_ kid] (contains? @secrets kid))
      (-kids [_] (set (keys @secrets)))
      (-alg [_ kid] (:alg (get @secrets kid)))
      (-with-material [_ kid f]
        (let [m (copy-bytes (:material (get @secrets kid)))]
          (try (f m)
               (finally #?(:clj (wipe! m))))))
      (-export [_ kid] (copy-bytes (:material (get @secrets kid))))
      (-destroy! [_ kid]
        (let [[old _] (swap-vals! secrets dissoc kid)]
          (when-let [m (get-in old [kid :material])]
            #?(:clj (wipe! m))
            true))))))

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

(defn register-vault!
  "Register vault id with provider (default: default-provider). Returns id.
   Impure: writes the vault registry. Throws ex-info {:type ::vault-exists}
   if id is already registered."
  ([id] (register-vault! id (default-provider)))
  ([id provider]
   (let [v {:id id :provider provider :public (atom {}) :defaults (atom {}) :shared (atom {})}
         [old _] (swap-vals! vaults (fn [m] (if (contains? m id) m (assoc m id v))))]
     (when (contains? old id)
       (throw (ex-info (str "Vault " id " is already registered") {:type ::vault-exists :vault id})))
     id)))

(defn unregister-vault!
  "Remove vault id from the registry, destroying every secret it holds.
   Impure: writes the registry and the provider. Returns nil."
  [id]
  (when-let [v (get @vaults id)]
    (doseq [kid (-kids (:provider v))]
      (-destroy! (:provider v) kid))
    (swap! vaults dissoc id))
  nil)

(defn vault-ids
  "The registered vault ids. Impure: reads the registry."
  []
  (set (keys @vaults)))

(defn- vault
  "The vault named id. Throws ::unknown-vault, never falls back."
  [id]
  (or (get @vaults id)
      (throw (ex-info (str "Unknown vault " (pr-str id)) {:type ::unknown-vault :vault id}))))

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
   through generation and import). Impure: writes the public side."
  ([pub] (register-public-key! :default pub))
  ([vault-id pub]
   (let [pub (key/public-key pub)
         kid (key/kid pub)]
     (swap! (:public (vault vault-id)) assoc kid pub)
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
   private key, else nil. Impure: reads the vault."
  ([kid] (handle :default kid))
  ([vault-id kid]
   (when (-has? (:provider (vault vault-id)) kid)
     (->handle vault-id kid))))

(defn handles
  "Handles for every key vault's secret side (default :default) holds.
   Impure: reads the vault."
  ([] (handles :default))
  ([vault-id]
   (set (map #(->handle vault-id %) (-kids (:provider (vault vault-id)))))))

(defn- check-handle [h what]
  (when-not (handle? h)
    (throw (ex-info (str what " needs a key handle")
                    {:type ::not-a-handle :got (str (type h))})))
  h)

(defn- provider-of
  "The provider holding h's key. Throws ::unknown-vault, or
   ::destroyed-key when the vault does not hold it (never held, or
   destroyed)."
  [h]
  (let [p (:provider (vault (:vault h)))]
    (when-not (-has? p (:kid h))
      (throw (ex-info "The vault does not hold this key (destroyed, or never held)"
                      {:type ::destroyed-key :kid (:kid h) :vault (:vault h)})))
    p))

(defn with-material
  "Call (f material) with h's secret material and return f's result.
   INTERNAL to signet's crypto code: material is valid only during f and
   must not be kept, returned or logged. Impure: reads the vault."
  [h f]
  (check-handle h "with-material")
  (-with-material (provider-of h) (:kid h) f))

;; ============================================================
;; Keys are born in the vault
;; ============================================================

(defn- add-key!
  "Record a key the provider now holds: its public key on the public side.
   Returns its handle."
  [vault-id pub]
  (let [kid (key/kid pub)]
    (swap! (:public (vault vault-id)) assoc kid pub)
    (->handle vault-id kid)))

(defn generate-signing-key!
  "Create a new Ed25519 signing key inside vault (default :default) and
   return its handle. The seed is born in the provider and never leaves it
   (under :sodium it never touches the Clojure heap).
   Impure: draws from the CSPRNG and writes the vault."
  ([] (generate-signing-key! :default))
  ([vault-id]
   (add-key! vault-id (-generate! (:provider (vault vault-id)) :ed25519))))

(defn generate-encryption-key!
  "Create a new X25519 encryption key inside vault (default :default) and
   return its handle. Impure: draws from the CSPRNG and writes the vault."
  ([] (generate-encryption-key! :default))
  ([vault-id]
   (add-key! vault-id (-generate! (:provider (vault vault-id)) :x25519))))

(defn- check-secret-bytes [x what]
  (when-not (and #?(:clj (bytes? x) :cljs false) (= 32 (alength ^bytes x)))
    (throw (ex-info (str what " must be 32 bytes")
                    {:type ::bad-secret :what what :got (str (type x))}))))

(defn- import-key! [vault-id alg secret-bytes]
  (try
    (add-key! vault-id (-import! (:provider (vault vault-id)) alg secret-bytes))
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
   ::not-a-handle, ::unknown-vault or ::destroyed-key."
  [h ack]
  (check-handle h "export-secret")
  (when-not (= export-acknowledgement ack)
    (throw (ex-info "export-secret needs {:i-understand :exposes-secret}"
                    {:type ::export-not-acknowledged})))
  (-export (provider-of h) (:kid h)))

(defn destroy!
  "Wipe and remove h's secret from its vault. The public key stays on the
   public side. Later use of h throws ::destroyed-key; destroying again is
   a no-op. Impure: writes the vault. Returns nil."
  [h]
  (check-handle h "destroy!")
  (-destroy! (:provider (vault (:vault h))) (:kid h))
  (swap! (:defaults (vault (:vault h)))
         (fn [d] (into {} (remove (fn [[_ v]] (= v h)) d))))
  nil)

(defn ^:no-doc adopt-shared!
  "INTERNAL to signet.shared: store derived symmetric material (bytes or a
   nacljc secret; the vault takes ownership) under kid in vault-id, with
   its public metadata. If the vault already holds kid, the new material is
   released instead (the same relationship derives the same key). Returns
   the handle. Impure: writes the vault."
  [vault-id kid material meta]
  (let [v (vault vault-id)]
    (if (-has? (:provider v) kid)
      #?(:clj (impl/destroy-material! material) :cljs nil)
      (-adopt! (:provider v) kid :shared material))
    (swap! (:shared v) assoc kid meta)
    (->handle vault-id kid)))

(defn ^:no-doc shared-meta
  "INTERNAL to signet.shared: the public metadata of shared key h, or nil."
  [h]
  (get @(:shared (vault (:vault h))) (:kid h)))

(defn public-key
  "The public key record of h's key. Impure: reads the vault's public side.
   Throws ::not-a-handle or ::unknown-vault."
  [h]
  (check-handle h "public-key")
  (or (get @(:public (vault (:vault h))) (:kid h))
      (key/lookup (:kid h))))

(defn algorithm
  "h's algorithm, :ed25519 or :x25519. Impure: reads the vault."
  [h]
  (check-handle h "algorithm")
  (-alg (provider-of h) (:kid h)))

;; ============================================================
;; Operations
;; ============================================================

(defn ^:no-doc x25519-dh
  "INTERNAL to signet's crypto code (box, shared keys): the X25519 shared
   secret of h's key (X25519, or Ed25519 converted inside the call) and
   their X25519 public key bytes: a byte array, or under the :sodium
   provider a nacljc secret. The caller must release it with
   impl/destroy-material! as soon as it is consumed. Impure: reads the vault.
   Throws ::not-a-handle, ::unknown-vault or ::destroyed-key."
  [h their-x25519-pub]
  (check-handle h "x25519-dh")
  (let [p (provider-of h) kid (:kid h)]
    #?(:clj  (-with-material
              p kid
              (fn [m]
                (case (-alg p kid)
                  :x25519  (impl/x25519-dh m their-x25519-pub)
                  :ed25519 (let [xsk (impl/ed25519-seed->x25519-private m)]
                             (try (impl/x25519-dh xsk their-x25519-pub)
                                  (finally (impl/destroy-material! xsk)))))))
       :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript")))))

(defn sign
  "Ed25519 signature (64 bytes) of message bytes with h's key. The seed is
   lent to the signing call only. Impure: reads the vault.
   Throws ::not-a-handle, ::unknown-vault, ::destroyed-key, or
   ::wrong-algorithm for a non-signing key."
  [h message-bytes]
  (check-handle h "sign")
  (let [p (provider-of h)]
    (when-not (= :ed25519 (-alg p (:kid h)))
      (throw (ex-info "sign needs an Ed25519 signing key" {:type ::wrong-algorithm :kid (:kid h)})))
    #?(:clj  (-with-material p (:kid h) #(impl/ed25519-sign % message-bytes))
       :cljs (throw (js/Error. "signet.vault not yet implemented for ClojureScript")))))

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
           h)))))
