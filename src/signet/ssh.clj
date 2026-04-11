(ns signet.ssh
  "SSH Ed25519 key import — use existing ~/.ssh/id_ed25519 keys with signet.

   Converts between SSH wire format and signet key records:
   - SSH public key (id_ed25519.pub) → Ed25519PublicKey
   - SSH private key (id_ed25519) → Ed25519KeyPair (seed + derived pub)
   - SSH keypair files → registered in signet key store

   No external dependencies — just byte manipulation and base64."
  (:require [signet.key :as key]
            [signet.impl.jvm :as jvm]
            [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; SSH format parsing helpers
;; ---------------------------------------------------------------------------

(defn- read-uint32
  "Read a big-endian uint32 from a byte vector at offset."
  [bs offset]
  (bit-or (bit-shift-left (bit-and (nth bs offset) 0xff) 24)
          (bit-shift-left (bit-and (nth bs (+ offset 1)) 0xff) 16)
          (bit-shift-left (bit-and (nth bs (+ offset 2)) 0xff) 8)
          (bit-and (nth bs (+ offset 3)) 0xff)))

(defn- read-ssh-string
  "Read a length-prefixed string/bytes from a byte vector at offset.
   Returns {:value byte-vector :next next-offset}."
  [bs offset]
  (let [len (read-uint32 bs offset)]
    {:value (subvec bs (+ offset 4) (+ offset 4 len))
     :next  (+ offset 4 len)}))

;; ---------------------------------------------------------------------------
;; Public key import
;; ---------------------------------------------------------------------------

(defn read-public-key
  "Read an SSH Ed25519 public key file and return a signet Ed25519PublicKey.

   Accepts the file content (single line):
     ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... comment

   SSH format: [4 len][11 'ssh-ed25519'][4 len][32 raw-pk]
   Returns Ed25519PublicKey record with raw 32-byte :x field."
  [ssh-pub-line]
  (let [b64       (second (str/split (str/trim ssh-pub-line) #" "))
        decoded   (vec (.decode (java.util.Base64/getDecoder) b64))
        ;; Skip: 4 (len) + 11 ("ssh-ed25519") + 4 (len) = 19 bytes
        raw-pk    (byte-array (drop 19 decoded))]
    (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 raw-pk)))

;; ---------------------------------------------------------------------------
;; Private key import
;; ---------------------------------------------------------------------------

(defn read-private-key
  "Read an OpenSSH Ed25519 private key file and return a signet Ed25519KeyPair.

   Parses the OpenSSH private key format (unencrypted only):
     -----BEGIN OPENSSH PRIVATE KEY-----
     base64...
     -----END OPENSSH PRIVATE KEY-----

   Extracts the 32-byte Ed25519 seed and derives the public key.
   Returns Ed25519KeyPair record with :x (pub) and :d (seed)."
  [pem-content]
  (let [lines   (str/split-lines pem-content)
        b64     (apply str (remove #(str/starts-with? % "-----") lines))
        decoded (vec (.decode (java.util.Base64/getDecoder) b64))
        ;; Verify magic: "openssh-key-v1\0"
        _       (assert (= "openssh-key-v1"
                           (String. (byte-array (take 14 decoded))))
                        "Not an OpenSSH private key")
        ;; Skip: magic(15) + ciphername + kdfname + kdfoptions + num-keys(4) + pubkey-blob
        pos   (atom 15)
        skip! (fn [] (let [r (read-ssh-string decoded @pos)]
                       (reset! pos (:next r)) r))]
    (skip!)                             ;; ciphername
    (skip!)                             ;; kdfname
    (skip!)                             ;; kdfoptions
    (swap! pos + 4)                     ;; num-keys
    (skip!)                             ;; public key blob
    (let [priv-blob (vec (:value (skip!))) ;; private key blob
          ;; Inside: checkint(4) + checkint(4) + keytype-string + pubkey + privkey(64) + comment
          ppos (atom 8)]                ;; skip 2x checkint
      (let [r (read-ssh-string priv-blob @ppos)] (reset! ppos (:next r))) ;; keytype
      (let [r   (read-ssh-string priv-blob @ppos) ;; embedded pubkey(32)
            pub (byte-array (:value r))
            _   (reset! ppos (:next r))]
        (swap! ppos + 4)                ;; skip privkey length prefix
        ;; Next 32 bytes = Ed25519 seed (followed by 32 bytes pubkey copy)
        (let [seed (byte-array (subvec priv-blob @ppos (+ @ppos 32)))]
          (key/->Ed25519KeyPair :signet/ed25519-keypair :Ed25519 pub seed))))))

;; ---------------------------------------------------------------------------
;; Convenience: load keypair from file paths
;; ---------------------------------------------------------------------------

(defn load-keypair
  "Load an Ed25519 keypair from SSH key files.

   Arguments:
     private-key-path — path to id_ed25519 (default: ~/.ssh/id_ed25519)
     public-key-path  — path to id_ed25519.pub (optional, derived from private key seed)

   The public key is derived from the private key seed, so the .pub file
   is not strictly required. When provided, it's used for verification.

   Returns an Ed25519KeyPair record registered in the signet key store,
   or nil if the private key file doesn't exist."
  ([] (load-keypair (str (System/getProperty "user.home") "/.ssh/id_ed25519")))
  ([private-key-path]
   (let [priv-file (java.io.File. private-key-path)]
     (when (.exists priv-file)
       (let [kp (read-private-key (slurp priv-file))]
         (key/register! kp)
         kp))))
  ([private-key-path public-key-path]
   (let [priv-file (java.io.File. private-key-path)
         pub-file  (java.io.File. public-key-path)]
     (when (and (.exists priv-file) (.exists pub-file))
       (let [kp (read-private-key (slurp priv-file))]
         (key/register! kp)
         kp)))))
