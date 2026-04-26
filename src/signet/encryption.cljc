(ns signet.encryption
  "Authenticated encryption between signet identities.

   Layered on signet.key's X25519 Diffie–Hellman, with HKDF-SHA-256
   key derivation and ChaCha20-Poly1305 AEAD. Bb-compatible (JCA only,
   no BouncyCastle required for symmetric primitives).

   Two patterns:

     (box sender-kp recipient-pub plaintext)         → ciphertext
     (unbox recipient-kp sender-pub ciphertext)      → plaintext
       — sender-authenticated. Static-static X25519 DH between sender's
         private and recipient's public. Either side can compute the
         same shared secret; an attacker without sender's private key
         cannot. Replay-protected only by the embedded random nonce —
         use a session abstraction (or unique AAD per message) for
         strong replay protection.

     (seal recipient-pub plaintext)                  → ciphertext
     (unseal recipient-kp ciphertext)                → plaintext
       — anonymous-sender (libsodium sealed-box style). Sender
         generates a fresh ephemeral keypair; ephemeral pub is included
         in the ciphertext envelope; recipient decrypts via their
         static private key + the embedded ephemeral pub. (Coming in
         a future version; stubbed for now.)

   Wire format for box:
     12-byte nonce || ChaCha20-Poly1305(key=HKDF(dh,info), nonce, pt, aad)

   The HKDF info field is set to a fixed protocol tag
   (\"signet/box/v1\") so future versions can be distinguished without
   key collision. AAD (additional authenticated data) is supported
   via opts {:aad <bytes>} and authenticated alongside the plaintext."
  (:require [signet.key :as key]
            #?(:clj [signet.impl.jvm :as jvm])))

(def ^:private ^String box-info-v1 "signet/box/v1")

#?(:clj
   (defn- info-bytes [^String s]
     (.getBytes s "UTF-8")))

#?(:clj
   (defn- derive-aead-key
     "HKDF-Expand the 32-byte X25519 shared secret to a 32-byte
      ChaCha20-Poly1305 key. Different `info` tags isolate keyspaces
      across protocol versions / use cases."
     [^bytes shared-secret ^String info]
     (jvm/hkdf-sha-256 shared-secret
                       (byte-array 0)        ; salt: empty
                       (info-bytes info)     ; info: protocol tag
                       32)))                 ; output: 32 bytes (ChaCha20 key)

(defn box
  "Encrypt `plaintext-bytes` from `sender-kp` to `recipient-pub`.
   Returns ciphertext bytes: nonce(12) || aead-ciphertext-with-tag.

   `sender-kp` must contain a private key (any signing or encryption
   keypair — Ed25519 keypairs are auto-converted to X25519).
   `recipient-pub` may be a public key or keypair; only the public part
   is used. Ed25519 keys are auto-converted.

   `opts` (optional):
     :aad <bytes>  Additional authenticated data — covered by the AEAD
                   tag but not encrypted. Useful for binding the
                   ciphertext to a context (ceremony id, recipient
                   identity, sequence number, etc)."
  ([sender-kp recipient-pub plaintext-bytes]
   (box sender-kp recipient-pub plaintext-bytes nil))
  ([sender-kp recipient-pub plaintext-bytes {:keys [aad] :as _opts}]
   #?(:clj
      (let [shared      (key/raw-shared-secret sender-kp recipient-pub)
            shared-bytes (:k shared)
            aead-key    (derive-aead-key shared-bytes box-info-v1)
            nonce       (jvm/random-bytes 12)
            ct          (jvm/chacha20-poly1305-encrypt aead-key nonce plaintext-bytes aad)
            out         (byte-array (+ 12 (count ct)))]
        (System/arraycopy nonce 0 out 0 12)
        (System/arraycopy ct 0 out 12 (count ct))
        out)
      :cljs
      (throw (js/Error. "signet.encryption not yet implemented for ClojureScript")))))

(defn unbox
  "Decrypt a `box`-formatted ciphertext using `recipient-kp` (must
   contain a private key) and `sender-pub` (the claimed sender's
   public key — the AEAD authentication will fail if this doesn't
   match the actual sender). Returns plaintext bytes.

   Throws on tampered ciphertext / wrong sender / wrong recipient.

   `opts`:
     :aad <bytes>  Same AAD that was supplied to `box`. Must match
                   exactly or decryption fails."
  ([recipient-kp sender-pub ciphertext-bytes]
   (unbox recipient-kp sender-pub ciphertext-bytes nil))
  ([recipient-kp sender-pub ciphertext-bytes {:keys [aad] :as _opts}]
   #?(:clj
      (let [shared      (key/raw-shared-secret recipient-kp sender-pub)
            shared-bytes (:k shared)
            aead-key    (derive-aead-key shared-bytes box-info-v1)
            n           (count ciphertext-bytes)
            _           (when (< n 28) ; 12 nonce + ≥ 16 tag
                          (throw (ex-info "ciphertext too short for box format"
                                          {:length n})))
            nonce       (java.util.Arrays/copyOfRange ciphertext-bytes 0 12)
            ct          (java.util.Arrays/copyOfRange ciphertext-bytes 12 n)]
        (jvm/chacha20-poly1305-decrypt aead-key nonce ct aad))
      :cljs
      (throw (js/Error. "signet.encryption not yet implemented for ClojureScript")))))
