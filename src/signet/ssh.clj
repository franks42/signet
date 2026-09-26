(ns signet.ssh
  "SSH Ed25519 key import — use existing ~/.ssh/id_ed25519 keys with signet.

   Converts between SSH wire format and signet key records:
   - SSH public key (id_ed25519.pub) → Ed25519PublicKey
   - SSH private key (id_ed25519) → Ed25519KeyPair (seed + derived pub)
   - SSH private key file → a vault handle (import-keypair!, 0.9.0)
   - SSH keypair files → Ed25519KeyPair (load-keypair; load-keypair! also
     registers it in the key store); deprecated since 0.9.0

   No external dependencies — just byte manipulation and base64."
  (:require [signet.key :as key]
            [signet.vault :as vault]
            [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; SSH format parsing helpers
;;
;; Strict: anything but an unencrypted Ed25519 key is refused with
;; ex-info {:type ::bad-ssh-key :reason …}, never parsed into a wrong key.
;; Error data names the reason, never key bytes.
;; ---------------------------------------------------------------------------

(defn- bad-key! [reason msg]
  (throw (ex-info (str "Not a usable SSH Ed25519 key: " msg)
                  {:type ::bad-ssh-key :reason reason})))

(defn- read-uint32
  "Big-endian uint32 from byte vector bs at offset (bounds-checked)."
  [bs offset]
  (when (> (+ offset 4) (count bs)) (bad-key! :truncated "truncated"))
  (bit-or (bit-shift-left (bit-and (nth bs offset) 0xff) 24)
          (bit-shift-left (bit-and (nth bs (+ offset 1)) 0xff) 16)
          (bit-shift-left (bit-and (nth bs (+ offset 2)) 0xff) 8)
          (bit-and (nth bs (+ offset 3)) 0xff)))

(defn- read-ssh-string
  "A length-prefixed string/bytes from byte vector bs at offset
   (bounds-checked). Returns {:value byte-vector :next next-offset}."
  [bs offset]
  (let [len (read-uint32 bs offset)
        end (+ offset 4 len)]
    (when (> end (count bs)) (bad-key! :truncated "truncated"))
    {:value (subvec bs (+ offset 4) end)
     :next  end}))

(defn- bytes->str [v] (String. (byte-array v) "UTF-8"))

(defn- base64-decode [^String s]
  (try (vec (.decode (java.util.Base64/getDecoder) s))
       (catch IllegalArgumentException _ (bad-key! :bad-base64 "not base64"))))

(defn- ed25519-public-blob
  "The 32-byte public key inside an SSH public-key blob
   (string \"ssh-ed25519\" + string pk)."
  [blob]
  (let [t  (read-ssh-string blob 0)
        pk (read-ssh-string blob (:next t))]
    (when-not (= "ssh-ed25519" (bytes->str (:value t)))
      (bad-key! :not-ed25519 (str "key type " (pr-str (bytes->str (:value t))))))
    (when-not (= 32 (count (:value pk)))
      (bad-key! :bad-length "the public key is not 32 bytes"))
    (:value pk)))

;; ---------------------------------------------------------------------------
;; Public key import
;; ---------------------------------------------------------------------------

(defn read-public-key
  "Read an SSH Ed25519 public key file and return a signet Ed25519PublicKey.

   Accepts the file content (single line):
     ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... comment

   SSH format: string \"ssh-ed25519\" + string raw-pk (32 bytes).
   Pure: parses the content; never touches the key store.
   Throws ex-info {:type ::bad-ssh-key :reason …} for anything else (another
   key type, truncated or malformed input)."
  [ssh-pub-line]
  (let [[kind b64] (str/split (str/trim (str ssh-pub-line)) #"\s+")]
    (when-not (= "ssh-ed25519" kind)
      (bad-key! :not-ed25519 (str "key type " (pr-str kind))))
    (when-not b64 (bad-key! :truncated "no key data"))
    (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519
                            (byte-array (ed25519-public-blob (base64-decode b64))))))

;; ---------------------------------------------------------------------------
;; Private key import
;; ---------------------------------------------------------------------------

(defn- parse-private-key
  "Read an OpenSSH Ed25519 private key file and return a signet Ed25519KeyPair.

   Parses the OpenSSH private key format, unencrypted only:
     -----BEGIN OPENSSH PRIVATE KEY-----
     base64...
     -----END OPENSSH PRIVATE KEY-----

   Checks, in order: the openssh-key-v1 magic; cipher and KDF \"none\"
   (passphrase-protected keys are refused, not parsed as ciphertext); one
   key; key type ssh-ed25519; the two check-ints agree (OpenSSH's
   integrity check); the public key in the public blob, in the private
   section and in the copy after the seed all agree.

   Pure: parses the content; never touches the key store.
   Throws ex-info {:type ::bad-ssh-key :reason …} when any check fails."
  [pem-content]
  (let [lines   (str/split-lines (str pem-content))
        b64     (apply str (map str/trim (remove #(str/starts-with? % "-----") lines)))
        decoded (base64-decode b64)
        magic   "openssh-key-v1"]
    (when-not (and (> (count decoded) 15)
                   (= magic (bytes->str (subvec decoded 0 14)))
                   (zero? (nth decoded 14)))
      (bad-key! :not-openssh "not an OpenSSH private key"))
    (let [cipher  (read-ssh-string decoded 15)
          kdf     (read-ssh-string decoded (:next cipher))
          kdfopts (read-ssh-string decoded (:next kdf))
          nkeys   (read-uint32 decoded (:next kdfopts))
          pubblob (read-ssh-string decoded (+ 4 (:next kdfopts)))
          priv    (read-ssh-string decoded (:next pubblob))]
      (when-not (and (= "none" (bytes->str (:value cipher)))
                     (= "none" (bytes->str (:value kdf))))
        (bad-key! :encrypted "passphrase-protected keys are not supported; decrypt it first (ssh-keygen -p)"))
      (when-not (= 1 nkeys) (bad-key! :key-count (str nkeys " keys in one file")))
      (let [pub      (ed25519-public-blob (:value pubblob))
            blob     (:value priv)
            check1   (read-uint32 blob 0)
            check2   (read-uint32 blob 4)
            ktype    (read-ssh-string blob 8)
            pub2     (read-ssh-string blob (:next ktype))
            secret   (read-ssh-string blob (:next pub2))
            sk       (:value secret)]
        (when-not (= check1 check2) (bad-key! :check-int-mismatch "the check-ints differ (corrupt or wrongly decrypted)"))
        (when-not (= "ssh-ed25519" (bytes->str (:value ktype)))
          (bad-key! :not-ed25519 "the private key is not ssh-ed25519"))
        (when-not (= 64 (count sk)) (bad-key! :bad-length "the private key is not 64 bytes"))
        (when-not (= pub (:value pub2) (subvec sk 32 64))
          (bad-key! :public-key-mismatch "the public key copies disagree"))
        (key/->Ed25519KeyPair :signet/ed25519-keypair :Ed25519
                              (byte-array pub) (byte-array (subvec sk 0 32)))))))

(defn ^{:deprecated "0.9.0"} read-private-key
  "DEPRECATED since 0.9.0 (secret-carrying key records): use import-keypair!,
   which puts the key in the vault and returns a handle.

   Read an OpenSSH Ed25519 private key file's content and return a signet
   Ed25519KeyPair. Unencrypted only; see parse-private-key for the checks.
   Pure: parses the content; never touches the key store.
   Throws ex-info {:type ::bad-ssh-key :reason …} when any check fails."
  [pem-content]
  (parse-private-key pem-content))

;; ---------------------------------------------------------------------------
;; Convenience: load keypair from file paths
;; ---------------------------------------------------------------------------

(defn ^{:deprecated "0.9.0"} load-keypair
  "DEPRECATED since 0.9.0 (secret-carrying key records): use import-keypair!.

   Load an Ed25519 keypair from SSH key files. Never touches the key store;
   load-keypair! also registers the result.

   Arguments:
     private-key-path — path to id_ed25519 (default: ~/.ssh/id_ed25519)
     public-key-path  — path to id_ed25519.pub (optional, derived from private key seed)

   The public key is derived from the private key seed, so the .pub file
   is not strictly required. When provided, both files must exist.

   Impure: reads the files (and the user.home property for the default
   path). Returns an Ed25519KeyPair record, or nil if a file doesn't exist."
  ([] (load-keypair (str (System/getProperty "user.home") "/.ssh/id_ed25519")))
  ([private-key-path]
   (let [priv-file (java.io.File. private-key-path)]
     (when (.exists priv-file)
       (parse-private-key (slurp priv-file)))))
  ([private-key-path public-key-path]
   (let [priv-file (java.io.File. private-key-path)
         pub-file  (java.io.File. public-key-path)]
     (when (and (.exists priv-file) (.exists pub-file))
       (parse-private-key (slurp priv-file))))))

(defn import-keypair!
  "Import an unencrypted OpenSSH Ed25519 private key file (default
   ~/.ssh/id_ed25519) into vault (default :default) and return its handle,
   or nil if the file does not exist. The seed goes into the vault and the
   parsed copy is wiped (the file's contents, as read, stay on the heap
   until collected). The vault's key must match the file's public key.
   On babashka this needs the libsodium backend (as vault/import-signing-key!).
   Impure: reads the file (and the user.home property for the default path)
   and writes the vault.
   Throws ex-info {:type ::bad-ssh-key :reason …} for anything but an
   unencrypted Ed25519 key, or :public-key-mismatch when the seed does not
   give the file's public key."
  ([] (import-keypair! (str (System/getProperty "user.home") "/.ssh/id_ed25519")))
  ([private-key-path] (import-keypair! :default private-key-path))
  ([vault-id private-key-path]
   (let [f (java.io.File. ^String private-key-path)]
     (when (.exists f)
       (let [kp (parse-private-key (slurp f))
             h  (vault/import-signing-key! vault-id (:d kp))]
         (when-not (= (:kid h) (key/kid (key/signing-public-key kp)))
           (vault/destroy! h)
           (bad-key! :public-key-mismatch "the seed does not give the file's public key"))
         h)))))

(defn ^{:deprecated "0.9.0"} load-keypair!
  "DEPRECATED since 0.9.0 (secret-carrying key records): use import-keypair!.

   load-keypair, then register! the keypair when one was found; returns it
   (or nil). Same arities. Impure: reads the files and writes the key store."
  [& paths]
  (some-> (apply load-keypair paths) key/register!))
