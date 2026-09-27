(ns signet.vault.file
  "Vault files: a vault saved to disk and reopened with a password
   (docs/10-password-unlocking.md, slice 2). Only ciphertext is ever on
   disk, and under the :sodium provider secret bytes stay in guarded memory
   the whole way: password -> Argon2id key -> master key -> identity keys.

     (create! :default \"vault.edn\" password {:limits :moderate}) ; saves the vault as it is
     (open! :default \"vault.edn\")          ; the vault, locked
     (unlock! :default password)            ; loads the keys
     (save! :default)                       ; explicit (default), or {:auto-save true}
     (lock! :default)                       ; destroys every secret in the vault
     (change-password! :default old new)
     (add-recovery-key! :default {:i-understand :exposes-secret}) ; optional; bytes to show once
     (unlock-with-recovery-key! :default rk) (reset-password! :default new)
     (remove-recovery-key! :default)        (status :default)

   Passwords and recovery keys are byte arrays (the UTF-8 of what was
   typed), wiped by every function that takes one; a String cannot be
   wiped, so it is refused.

   What is saved: identity keys (Ed25519, X25519), the public side (which
   peers the vault knows: encrypted too) and the default signing key. Not
   saved: shared keys and password keys (derive them again), and session
   entries (a session does not outlive the process).

   A locked vault holds nothing: operations that need one of its keys
   throw :signet.vault/vault-locked, and so do generating, importing and
   registering keys. Handles stay valid values and work again after
   unlocking.

   The file (canonical EDN, mode 0600, written to a temporary file and
   renamed):

     {:type :signet/vault-file :v 1
      :unlock [{:method :password :salt :opslimit :memlimit :nonce :wrapped}
               {:method :recovery-key :nonce :wrapped}]   ; optional
      :salt   24 random bytes, new on every save
      :body   ChaCha20-Poly1305 of the snapshot}

   Each :wrapped is the master key MK under an unlock key (Argon2id of the
   password; HKDF of the recovery key), with the entry's other slots as
   associated data. On each save, k = HKDF(MK, :salt, \"signet/vault-file/v1/save\")
   encrypts the body (nonce 0; associated data: the header) and wraps each
   identity key inside it (nonce i+1; associated data: its kid and
   algorithm).

   Needs the libsodium backend (Argon2id): on the JCA backend the
   functions that take a password throw :signet.impl/unsupported.

   Limits: a stolen file can be attacked offline; only Argon2id's cost
   stands between a weak password and the keys. An old copy of the file
   still opens with the password it had then (rollback is not detected).
   Without the password and without a recovery key, the keys are gone."
  (:require [cedn.core :as cedn]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [signet.impl :as impl]
            [signet.password :as password]
            [signet.vault :as vault])
  (:import (java.nio.file CopyOption Files OpenOption StandardCopyOption)
           (java.nio.file.attribute FileAttribute PosixFilePermissions)))

;; ============================================================
;; Small helpers
;; ============================================================

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))

(defn- wipe!
  "Overwrite bs with zeros. Impure: writes bs."
  [bs] (when (bytes? bs) (java.util.Arrays/fill ^bytes bs (byte 0))))

(defn- nonce
  "The 12-byte big-endian AEAD nonce for counter i. Pure."
  ^bytes [i]
  (let [n (byte-array 12)]
    (doseq [j (range 8)]
      (aset-byte n (- 11 j) (unchecked-byte (bit-shift-right i (* 8 j)))))
    n))

(defn- check-password
  "pw, if it is a byte array. Pure.
   Throws ex-info {:type ::bad-password} otherwise."
  [pw what]
  (when-not (bytes? pw)
    (throw (ex-info (str what " must be a byte array (a String cannot be wiped)")
                    {:type ::bad-password :got (str (type pw))})))
  pw)

(defn- wiping
  "Call (f) and wipe every byte array in arrays afterwards, whatever
   happens. Impure: wipes arrays."
  [arrays f]
  (try (f) (finally (run! wipe! arrays))))

;; ============================================================
;; File state (kept in the vault: signet.vault/file-state)
;;
;;   {:path :locked? :dirty? :auto-save? :on-change
;;    :file        the last file read or written (its parsed map)
;;    :unlock      the unlock entries to write
;;    :mk          the master key's entry id, while unlocked
;;    :unlocked-by :password | :recovery-key}
;; ============================================================

(defn- state
  "vault-id's file state atom. Impure: reads the vault.
   Throws ex-info {:type ::no-file} when the vault has no file, and
   :signet.vault/unknown-vault."
  [vault-id]
  (let [a (vault/file-state vault-id)]
    (when-not @a
      (throw (ex-info (str "Vault " (pr-str vault-id) " has no file (see create! and open!)")
                      {:type ::no-file :vault vault-id})))
    a))

(defn- unlocked-state
  "vault-id's file state atom, which must be unlocked. Impure: reads the vault.
   Throws ex-info {:type ::no-file} or {:type :signet.vault/vault-locked}."
  [vault-id]
  (let [a (state vault-id)]
    (when (:locked? @a)
      (throw (ex-info (str "Vault " (pr-str vault-id) " is locked: unlock it first")
                      {:type :signet.vault/vault-locked :vault vault-id})))
    a))

;; ============================================================
;; Reading and writing the file
;; ============================================================

(def ^:private unlock-slots
  {:password     #{:method :salt :opslimit :memlimit :nonce :wrapped}
   :recovery-key #{:method :nonce :wrapped}})

(defn- bytes-of? [x n] (and (bytes? x) (= n (alength ^bytes x))))

(defn- unlock-entry-ok?
  "Is e a well-formed unlock entry? Pure."
  [e]
  (and (map? e)
       (= (set (keys e)) (unlock-slots (:method e)))
       (bytes-of? (:nonce e) 12)
       (bytes-of? (:wrapped e) 48)
       (or (not= :password (:method e))
           (and (bytes-of? (:salt e) 16) (pos-int? (:opslimit e)) (pos-int? (:memlimit e))))))

(defn- file-ok?
  "Is f a well-formed vault file (version 1)? Pure."
  [f]
  (and (map? f)
       (= #{:type :v :unlock :salt :body} (set (keys f)))
       (= :signet/vault-file (:type f))
       (= 1 (:v f))
       (vector? (:unlock f))
       (seq (:unlock f))
       (every? unlock-entry-ok? (:unlock f))
       (apply distinct? (map :method (:unlock f)))
       (bytes-of? (:salt f) 24)
       (bytes? (:body f)) (<= 16 (alength ^bytes (:body f)))))

(defn- read-file
  "The vault file at path, parsed and checked. Impure: reads the file.
   Throws ex-info {:type ::bad-file} for a file that is missing, not EDN,
   or not a version-1 vault file."
  [path]
  (let [f (try (edn/read-string {:readers cedn/readers} (slurp path))
               (catch Exception e
                 (throw (ex-info (str "Cannot read vault file " path ": " (ex-message e))
                                 {:type ::bad-file :path (str path)}))))]
    (when-not (file-ok? f)
      (throw (ex-info (str path " is not a signet vault file (version 1)")
                      {:type ::bad-file :path (str path)})))
    f))

(defn- write-atomically!
  "Write text to path: to a temporary file in the same directory (mode
   0600 where the file system has POSIX permissions), then an atomic
   rename over path. Impure: writes files."
  [path ^String text]
  (let [target (.toAbsolutePath (.toPath (io/file path)))
        dir    (.getParent target)
        attrs  (into-array FileAttribute [(PosixFilePermissions/asFileAttribute
                                           (PosixFilePermissions/fromString "rw-------"))])
        tmp    (try (Files/createTempFile dir ".signet-vault-" ".tmp" attrs)
                    (catch UnsupportedOperationException _
                      (Files/createTempFile dir ".signet-vault-" ".tmp" (into-array FileAttribute []))))]
    (try
      (Files/write tmp (utf8 text) (into-array OpenOption []))
      (Files/move tmp target (into-array CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                     StandardCopyOption/REPLACE_EXISTING]))
      (finally (Files/deleteIfExists tmp)))))

;; ============================================================
;; Unlock entries: the master key wrapped under a password or recovery key
;; ============================================================

(defn- entry-aad
  "The associated data of unlock entry e: its slots but :wrapped. Pure."
  ^bytes [e]
  (cedn/canonical-bytes (assoc (dissoc e :wrapped) :type :signet/vault-file :v 1)))

(defn- password-entry
  "A new password unlock entry wrapping vault-id's master key under
   password (wiped). Impure: draws a salt and nonce, runs Argon2id in the
   vault's provider, reads the master key, wipes password."
  [vault-id mk ^bytes pw limits]
  (let [{:keys [opslimit memlimit] :as limits} (password/limits-of limits)
        salt (impl/random-bytes 16)
        e    {:method :password :salt salt :opslimit opslimit :memlimit memlimit
              :nonce (impl/random-bytes 12)}
        k    (vault/argon2id-material vault-id pw salt limits)]
    (try
      (assoc e :wrapped (vault/with-internal vault-id mk
                          #(impl/wrap-material k (:nonce e) % (entry-aad e))))
      (finally (impl/destroy-material! k)))))

(defn- recovery-unlock-key
  "The recovery key's unlock key, derived from rk-material. Pure for
   bytes; with a nacljc secret, impure: reads it and allocates the result."
  [rk-material]
  (impl/hkdf-sha-256 rk-material (byte-array 0) (utf8 "signet/vault-file/v1/recovery-key") 32))

(defn- unwrap-mk
  "The master key material of entry e, with unlock key k. Impure: reads k.
   Throws ex-info {:type :signet.impl/auth-failed} for a wrong key."
  [k e]
  (impl/unwrap-material k (:nonce e) (:wrapped e) (entry-aad e)))

(defn- entry
  "The unlock entry of method in unlock entries es, or nil. Pure."
  [es method]
  (first (filter #(= method (:method %)) es)))

;; ============================================================
;; The recovery key, for people: SIGNET-RK1-XXXX-…, Crockford base32 of
;; the 32 key bytes and a 3-byte checksum (56 symbols, 14 groups of 4)
;; ============================================================

(def ^:private rk-prefix "SIGNET-RK1-")
(def ^:private crockford "0123456789ABCDEFGHJKMNPQRSTVWXYZ")

(defn- rk-checksum
  "The first 3 bytes of SHA-256(\"signet-rk1\" ‖ rk). Pure."
  ^bytes [^bytes rk]
  (let [d (impl/sha-256 (byte-array (concat (utf8 "signet-rk1") rk)))]
    (java.util.Arrays/copyOf ^bytes d 3)))

(defn- format-recovery-key
  "rk (32 bytes) as the ASCII bytes of SIGNET-RK1-XXXX-…-XXXX. Built as
   bytes (never a String), so the caller can wipe it. Impure: writes a
   scratch array it wipes."
  ^bytes [^bytes rk]
  (let [data (byte-array 35)]
    (try
      (System/arraycopy rk 0 data 0 32)
      (System/arraycopy (rk-checksum rk) 0 data 32 3)
      (let [out (java.io.ByteArrayOutputStream. 80)]
        (.write out (utf8 rk-prefix) 0 (count rk-prefix))
        (loop [bit 0 sym 0]
          (when (< sym 56)
            (when (and (pos? sym) (zero? (mod sym 4))) (.write out (int \-)))
            (let [v (reduce (fn [acc b]
                              (let [i (+ bit b)]
                                (bit-or (bit-shift-left acc 1)
                                        (bit-and 1 (bit-shift-right (aget data (quot i 8)) (- 7 (mod i 8)))))))
                            0 (range 5))]
              (.write out (int (.charAt ^String crockford v)))
              (recur (+ bit 5) (inc sym)))))
        (.toByteArray out))
      (finally (wipe! data)))))

(defn- symbol-value
  "The Crockford value of ASCII byte c (case-insensitive; O is 0, I and L
   are 1), :skip for a separator, nil for anything else. Pure."
  [c]
  (let [ch (Character/toUpperCase (char (bit-and c 0xff)))]
    (cond
      (#{\- \space} ch) :skip
      (= \O ch)         0
      (#{\I \L} ch)     1
      :else             (let [i (.indexOf ^String crockford (str ch))] (when-not (neg? i) i)))))

(defn- parse-recovery-key
  "The 32 key bytes of a formatted recovery key (ASCII bytes). Pure but
   for scratch arrays it wipes.
   Throws ex-info {:type ::bad-recovery-key} for a wrong prefix, a symbol
   that is not Crockford base32, a wrong length or a wrong checksum (a
   typo)."
  ^bytes [^bytes s]
  (let [bad    #(throw (ex-info (str "Not a signet recovery key: " %) {:type ::bad-recovery-key}))
        n      (count rk-prefix)
        prefix (String. s 0 (min n (alength s)) "US-ASCII")]
    (when-not (= rk-prefix (str/upper-case prefix)) (bad "it must start with SIGNET-RK1-"))
    (let [vals (int-array 56)
          cnt  (loop [i n k 0]
                 (if (= i (alength s))
                   k
                   (let [v (symbol-value (aget s i))]
                     (cond (nil? v)     (bad "a character that is not in its alphabet")
                           (= :skip v)  (recur (inc i) k)
                           (>= k 56)    (bad "too long")
                           :else        (do (aset vals k (int v)) (recur (inc i) (inc k)))))))
          data (byte-array 35)]
      (try
        (when-not (= 56 cnt) (bad "too short"))
        (doseq [sym (range 56) b (range 5)
                :let [i (+ (* 5 sym) b)]
                :when (pos? (bit-and (aget vals sym) (bit-shift-left 1 (- 4 b))))]
          (aset-byte data (quot i 8) (unchecked-byte (bit-or (aget data (quot i 8))
                                                             (bit-shift-left 1 (- 7 (mod i 8)))))))
        (let [rk (java.util.Arrays/copyOf data 32)]
          (when-not (java.security.MessageDigest/isEqual (rk-checksum rk) (java.util.Arrays/copyOfRange data 32 35))
            (wipe! rk)
            (bad "the checksum does not match (a typo?)"))
          rk)
        (finally (wipe! data) (java.util.Arrays/fill vals (int 0)))))))

;; ============================================================
;; Saving and loading the body
;; ============================================================

(defn- secret-aad ^bytes [kid alg] (cedn/canonical-bytes {:kid kid :alg alg}))

(defn- save-key
  "k = HKDF(MK, salt, \"signet/vault-file/v1/save\"). Impure: reads the
   master key; under :sodium allocates the result."
  [vault-id mk salt]
  (vault/with-internal vault-id mk
    #(impl/hkdf-sha-256 % salt (utf8 "signet/vault-file/v1/save") 32)))

(defn- write-file!
  "Snapshot the vault, encrypt it and write the file. Impure: reads the
   vault, draws a salt, writes the file and the file state."
  [vault-id a]
  (let [{:keys [path unlock mk]} @a
        salt (impl/random-bytes 24)
        k    (save-key vault-id mk salt)]
    (try
      (let [content (vault/snapshot vault-id (fn [i kid alg m]
                                               (impl/wrap-material k (nonce (inc i)) m (secret-aad kid alg))))
            header  {:type :signet/vault-file :v 1 :unlock unlock :salt salt}
            f       (assoc header :body (impl/chacha20-poly1305-encrypt
                                         k (nonce 0) (cedn/canonical-bytes content)
                                         (cedn/canonical-bytes header)))]
        (write-atomically! path (cedn/canonical-str f))
        (swap! a assoc :file f :dirty? false)
        nil)
      (finally (impl/destroy-material! k)))))

(defn- load-body!
  "Decrypt file f's body with master key mk and load it into vault-id.
   Impure: reads the master key, writes the vault.
   Throws ex-info {:type ::corrupt-file} when the body fails
   authentication or does not parse, and :signet.vault/corrupt-entry."
  [vault-id mk f]
  (let [k (save-key vault-id mk (:salt f))]
    (try
      (let [content (try (edn/read-string {:readers cedn/readers}
                                          (String. ^bytes (impl/chacha20-poly1305-decrypt
                                                           k (nonce 0) (:body f)
                                                           (cedn/canonical-bytes (dissoc f :body)))
                                                   "UTF-8"))
                         (catch Exception _
                           (throw (ex-info "The vault file's body failed authentication (changed or damaged)"
                                           {:type ::corrupt-file}))))]
        (when-not (and (map? content) (vector? (:public content)) (vector? (:secrets content))
                       (every? #(and (string? (:kid %)) (bytes? (:wrapped %))) (:secrets content)))
          (throw (ex-info "The vault file's body is not a snapshot" {:type ::corrupt-file})))
        (vault/restore! vault-id content
                        (fn [i {:keys [kid alg wrapped]}]
                          (try (impl/unwrap-material k (nonce (inc i)) wrapped (secret-aad kid alg))
                               (catch clojure.lang.ExceptionInfo _
                                 (throw (ex-info "A key in the vault file failed authentication"
                                                 {:type ::corrupt-file :kid kid})))))))
      (finally (impl/destroy-material! k)))))

(defn- finish-unlock!
  "Adopt master-key material mk-m into vault-id, load the body, and mark
   the vault unlocked by method. On failure the vault is cleared and stays
   locked. Impure: writes the vault and the file state."
  [vault-id a mk-m method]
  (let [mk (vault/adopt-internal! vault-id mk-m)]
    (try
      (load-body! vault-id mk (:file @a))
      (swap! a assoc :locked? false :dirty? false :mk mk :unlocked-by method)
      vault-id
      (catch Throwable t
        (vault/clear! vault-id)
        (throw t)))))

(declare save!)

(defn- auto-saver
  "The :on-change of a vault file with :auto-save. Impure: writes the file."
  [vault-id]
  (fn [] (save! vault-id)))

;; ============================================================
;; Public API
;; ============================================================

(defn save!
  "Write vault-id's vault file: its identity keys, public side and default
   signing key, encrypted (see the namespace docstring). Atomic: a crash
   leaves the old file or the new one.
   Impure: reads the vault, draws from the CSPRNG, writes the file.
   Throws ex-info {:type ::no-file} when the vault has no file,
   {:type :signet.vault/vault-locked} when it is locked, and I/O errors."
  [vault-id]
  (let [a (unlocked-state vault-id)]
    (locking a (write-file! vault-id a))
    nil))

(defn create!
  "Give vault vault-id (registered if it is not; default provider) a new
   vault file at path, protected by password (a byte array, wiped), and
   save it: the vault's current keys go into the file. The vault stays
   unlocked. Returns vault-id.

   opts:
     :limits     Argon2id cost: :interactive, :moderate (default),
                 :sensitive, or {:opslimit n :memlimit bytes}
     :auto-save  true: save after every change (a key generated, imported
                 or destroyed; a public key registered; the default set).
                 Default false: call save!.

   Impure: may register the vault, draws from the CSPRNG, runs Argon2id,
   writes the vault and the file, wipes password.
   Throws ex-info {:type ::bad-password} unless password is a byte array,
   {:type ::file-exists} when path exists (never overwritten),
   {:type ::has-file} when the vault already has a file,
   :signet.password/bad-option for bad limits,
   :signet.vault/vault-locked, and :signet.impl/unsupported on the JCA
   backend."
  ([vault-id path password] (create! vault-id path password nil))
  ([vault-id path password {:keys [limits auto-save] :or {limits :moderate}}]
   (wiping [password]
           (fn []
             (check-password password "create!: the password")
             (when (.exists (io/file path))
               (throw (ex-info (str "create!: " path " exists; it is never overwritten")
                               {:type ::file-exists :path (str path)})))
             (let [new? (not (contains? (vault/vault-ids) vault-id))]
               (when new? (vault/register-vault! vault-id))
               (try
                 (let [a (vault/file-state vault-id)]
                   (when @a
                     (throw (ex-info (str "Vault " (pr-str vault-id) " already has a file")
                                     {:type ::has-file :vault vault-id})))
                   (let [mk (vault/generate-internal! vault-id 32)]
                     (try
                       (let [e (password-entry vault-id mk password limits)]
                         (reset! a {:path (str path) :locked? false :dirty? true :auto-save? (boolean auto-save)
                                    :unlock [e] :mk mk :unlocked-by :password
                                    :on-change (when auto-save (auto-saver vault-id))})
                         (try (save! vault-id)
                              (catch Throwable t (reset! a nil) (throw t))))
                       (catch Throwable t (vault/destroy-internal! vault-id mk) (throw t))))
                   vault-id)
                 (catch Throwable t
                   (when new? (vault/unregister-vault! vault-id))
                   (throw t))))))))

(defn open!
  "Open the vault file at path as vault vault-id, locked: registered if it
   is not (default provider), else it must be empty (the :default vault at
   start is). Unlock it with unlock!. Returns vault-id.
   opts: :auto-save, as in create!.
   Impure: reads the file, writes the vault registry and the vault.
   Throws ex-info {:type ::bad-file} for a missing or malformed file, and
   {:type ::vault-not-empty} when vault-id holds keys or has a file."
  ([vault-id path] (open! vault-id path nil))
  ([vault-id path {:keys [auto-save]}]
   (let [f    (read-file path)
         new? (not (contains? (vault/vault-ids) vault-id))]
     (when new? (vault/register-vault! vault-id))
     (when-not (vault/blank? vault-id)
       (throw (ex-info (str "Vault " (pr-str vault-id) " is not empty: open a file into a new or empty vault")
                       {:type ::vault-not-empty :vault vault-id})))
     (reset! (vault/file-state vault-id)
             {:path (str path) :locked? true :dirty? false :auto-save? (boolean auto-save)
              :file f :unlock (:unlock f)
              :on-change (when auto-save (auto-saver vault-id))})
     vault-id)))

(defn unlock!
  "Unlock vault-id with password (a byte array, wiped): derive the
   password key, unwrap the master key, load the keys. Nothing is loaded
   when the password is wrong. Returns vault-id.
   Impure: runs Argon2id, writes the vault, wipes password.
   Throws ex-info {:type ::bad-password} for a wrong password (or not a
   byte array), {:type ::already-unlocked}, {:type ::no-file},
   {:type ::no-password} when the file has no password entry,
   {:type ::corrupt-file} when the body fails authentication, and
   :signet.impl/unsupported on the JCA backend."
  [vault-id password]
  (wiping [password]
          (fn []
            (check-password password "unlock!: the password")
            (let [a (state vault-id)]
              (locking a
                (when-not (:locked? @a)
                  (throw (ex-info (str "Vault " (pr-str vault-id) " is already unlocked")
                                  {:type ::already-unlocked :vault vault-id})))
                (let [e (or (entry (:unlock @a) :password)
                            (throw (ex-info "This vault file has no password" {:type ::no-password})))
                      k (vault/argon2id-material vault-id password (:salt e)
                                                 (select-keys e [:opslimit :memlimit]))
                      m (try (unwrap-mk k e)
                             (catch clojure.lang.ExceptionInfo ex
                               (if (= :signet.impl/auth-failed (:type (ex-data ex)))
                                 (throw (ex-info "Wrong password" {:type ::bad-password :vault vault-id}))
                                 (throw ex)))
                             (finally (impl/destroy-material! k)))]
                  (finish-unlock! vault-id a m :password)))))))

(defn unlock-with-recovery-key!
  "Unlock vault-id with its recovery key: the bytes add-recovery-key!
   returned (or the UTF-8 of what was typed from them), wiped. Then set a
   new password with reset-password!. Returns vault-id.
   Impure: writes the vault, wipes rk.
   Throws ex-info {:type ::bad-recovery-key} for a malformed key (a typo is
   caught by its checksum), {:type ::wrong-recovery-key} for a well-formed
   key that does not open this vault, {:type ::no-recovery-key} when the
   file has none, {:type ::already-unlocked}, {:type ::no-file} and
   {:type ::corrupt-file}."
  [vault-id rk]
  (wiping [rk]
          (fn []
            (check-password rk "unlock-with-recovery-key!: the recovery key")
            (let [a (state vault-id)]
              (locking a
                (when-not (:locked? @a)
                  (throw (ex-info (str "Vault " (pr-str vault-id) " is already unlocked")
                                  {:type ::already-unlocked :vault vault-id})))
                (let [e   (or (entry (:unlock @a) :recovery-key)
                              (throw (ex-info "This vault file has no recovery key" {:type ::no-recovery-key})))
                      key (parse-recovery-key rk)
                      m   (vault/with-temp-material vault-id key
                            (fn [rk-m]
                              (let [k (recovery-unlock-key rk-m)]
                                (try (unwrap-mk k e)
                                     (catch clojure.lang.ExceptionInfo ex
                                       (if (= :signet.impl/auth-failed (:type (ex-data ex)))
                                         (throw (ex-info "This recovery key does not open this vault"
                                                         {:type ::wrong-recovery-key :vault vault-id}))
                                         (throw ex)))
                                     (finally (impl/destroy-material! k))))))]
                  (finish-unlock! vault-id a m :recovery-key)))))))

(defn lock!
  "Lock vault-id: destroy every secret it holds (identity, shared and
   password keys, session entries, the master key) and empty its public
   side. Open sessions in it end. Unlock again with unlock!.
   Refuses to lose unsaved changes unless opts has :discard-changes? true.
   Locking a locked vault does nothing. Returns vault-id.
   Impure: writes the vault.
   Throws ex-info {:type ::unsaved-changes} and {:type ::no-file}."
  ([vault-id] (lock! vault-id nil))
  ([vault-id {:keys [discard-changes?]}]
   (let [a (state vault-id)]
     (locking a
       (when-not (:locked? @a)
         (when (and (:dirty? @a) (not discard-changes?))
           (throw (ex-info (str "Vault " (pr-str vault-id) " has unsaved changes: save! first, or lock! with {:discard-changes? true}")
                           {:type ::unsaved-changes :vault vault-id})))
         (vault/clear! vault-id)
         (swap! a assoc :locked? true :dirty? false :mk nil :unlocked-by nil :unlock (:unlock (:file @a)))))
     vault-id)))

(defn change-password!
  "Replace vault-id's password: old must be the current one. The master
   key is rewrapped (the keys are untouched), and the file is saved at
   once. Both passwords are byte arrays, wiped.
   opts: :limits (default :moderate), as in create!.
   Impure: runs Argon2id twice, writes the file, wipes both passwords.
   Throws ex-info {:type ::bad-password} for a wrong old password (or not
   byte arrays), :signet.vault/vault-locked, {:type ::no-file}, and
   :signet.password/bad-option."
  ([vault-id old new] (change-password! vault-id old new nil))
  ([vault-id old new {:keys [limits] :or {limits :moderate}}]
   (wiping [old new]
           (fn []
             (check-password old "change-password!: the old password")
             (check-password new "change-password!: the new password")
             (let [a (unlocked-state vault-id)]
               (locking a
                 (let [e (entry (:unlock @a) :password)
                       k (when e (vault/argon2id-material vault-id old (:salt e) (select-keys e [:opslimit :memlimit])))]
                   (try
                     (when (or (nil? e) (try (impl/destroy-material! (unwrap-mk k e)) false
                                             (catch clojure.lang.ExceptionInfo _ true)))
                       (throw (ex-info "Wrong password" {:type ::bad-password :vault vault-id})))
                     (finally (impl/destroy-material! k))))
                 (let [e (password-entry vault-id (:mk @a) new limits)]
                   (swap! a update :unlock #(conj (vec (remove (comp #{:password} :method) %)) e))
                   (write-file! vault-id a))))
             vault-id))))

(defn reset-password!
  "Set a new password for vault-id without the old one: only after
   unlock-with-recovery-key!. The file is saved at once. new is a byte
   array, wiped. opts: :limits, as in create!.
   Impure: runs Argon2id, writes the file, wipes new.
   Throws ex-info {:type ::recovery-unlock-required} unless the vault was
   unlocked with its recovery key, :signet.vault/vault-locked,
   {:type ::bad-password} unless new is a byte array, and {:type ::no-file}."
  ([vault-id new] (reset-password! vault-id new nil))
  ([vault-id new {:keys [limits] :or {limits :moderate}}]
   (wiping [new]
           (fn []
             (check-password new "reset-password!: the new password")
             (let [a (unlocked-state vault-id)]
               (locking a
                 (when-not (= :recovery-key (:unlocked-by @a))
                   (throw (ex-info "reset-password! needs a vault unlocked with its recovery key (else use change-password!)"
                                   {:type ::recovery-unlock-required :vault vault-id})))
                 (let [e (password-entry vault-id (:mk @a) new limits)]
                   (swap! a update :unlock #(conj (vec (remove (comp #{:password} :method) %)) e))
                   (write-file! vault-id a))))
             vault-id))))

(def ^:private exposure-acknowledgement {:i-understand :exposes-secret})

(defn add-recovery-key!
  "Create a recovery key for vault-id (replacing any earlier one: it stops
   working) and save the file at once. Returns the key, once, as the ASCII
   bytes of SIGNET-RK1-XXXX-…-XXXX for the application to show or print:
   wipe them afterwards. signet never stores it; only the master key
   wrapped under it goes into the file. It gives full access with no
   Argon2id cost: keep it offline. Needs the acknowledgement
   {:i-understand :exposes-secret}.
   Impure: draws from the CSPRNG, writes the file.
   Throws ex-info {:type ::not-acknowledged}, :signet.vault/vault-locked
   and {:type ::no-file}."
  [vault-id ack]
  (when-not (= exposure-acknowledgement ack)
    (throw (ex-info "add-recovery-key! needs {:i-understand :exposes-secret}" {:type ::not-acknowledged})))
  (let [a (unlocked-state vault-id)]
    (locking a
      (let [rk        (impl/random-bytes 32)
            formatted (format-recovery-key rk)
            e         {:method :recovery-key :nonce (impl/random-bytes 12)}
            e         (assoc e :wrapped
                             (vault/with-temp-material vault-id rk
                               (fn [rk-m]
                                 (let [k (recovery-unlock-key rk-m)]
                                   (try (vault/with-internal vault-id (:mk @a)
                                          #(impl/wrap-material k (:nonce e) % (entry-aad e)))
                                        (finally (impl/destroy-material! k)))))))]
        (try
          (swap! a update :unlock #(conj (vec (remove (comp #{:recovery-key} :method) %)) e))
          (write-file! vault-id a)
          formatted
          (catch Throwable t (wipe! formatted) (throw t)))))))

(defn remove-recovery-key!
  "Revoke vault-id's recovery key (its wrapped master key leaves the file)
   and save the file at once. Does nothing when there is none. Returns
   vault-id.
   Impure: writes the file.
   Throws :signet.vault/vault-locked and {:type ::no-file}."
  [vault-id]
  (let [a (unlocked-state vault-id)]
    (locking a
      (when (entry (:unlock @a) :recovery-key)
        (swap! a update :unlock #(vec (remove (comp #{:recovery-key} :method) %)))
        (write-file! vault-id a)))
    vault-id))

(defn status
  "vault-id's file status, or nil when it has no file:
     {:path … :locked? … :dirty? … :auto-save? … :recovery-key? …
      :unlocked-by :password | :recovery-key | nil}
   Impure: reads the vault.
   Throws :signet.vault/unknown-vault."
  [vault-id]
  (when-let [s @(vault/file-state vault-id)]
    (-> (select-keys s [:path :locked? :dirty? :auto-save? :unlocked-by])
        (assoc :recovery-key? (boolean (entry (:unlock s) :recovery-key))))))
