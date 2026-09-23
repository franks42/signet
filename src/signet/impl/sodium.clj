(ns signet.impl.sodium
  "libsodium backend for signet, via sodium.core (babashka.ffi): the same
   16 functions and contracts as signet.impl.jvm (JCA). Selected through
   signet.impl; do not require directly.

   Requirements: libsodium >= 1.0.19 installed (e.g. brew install
   libsodium), sodium.cljc on the classpath (deps.edn alias :sodium), JDK 25+
   with --enable-native-access=ALL-UNNAMED on the JVM, bb >= 1.13.220.

   Differences from the JCA backend:
   - Seed -> public key uses crypto_sign_seed_keypair instead of the JCA
     'fake SecureRandom' trick, so it also works on babashka.
   - Fixed-size inputs are length-checked (sodium.core); a wrong size throws
     ex-info where JCA threw its own exception types.
   - Output is byte-identical to the JCA backend (see
     test/signet/backend_parity.clj)."
  (:require [sodium.core :as na]))

(def backend
  "This backend's name, as selected in signet.impl."
  :sodium)

(defn generate-ed25519-keypair
  "Generate an Ed25519 keypair. Returns [public-key-bytes private-key-seed-bytes]."
  []
  (let [seed (na/random-bytes 32)
        [pk _] (na/seed->keypair seed)]
    [pk seed]))

(defn ed25519-seed->public-key
  "Derive the Ed25519 public key (32 bytes) from a seed (32 bytes)."
  [seed-bytes]
  (first (na/seed->keypair seed-bytes)))

(defn sha-256
  "Compute SHA-256 hash of byte array. Returns 32-byte hash."
  [bs]
  (na/sha-256 bs))

(defn ed25519-sign
  "Sign message bytes with an Ed25519 private key seed (32 bytes).
   Returns 64-byte signature."
  [seed-bytes message-bytes]
  (na/sign (second (na/seed->keypair seed-bytes)) message-bytes))

(defn ed25519-verify
  "Verify an Ed25519 signature. Returns true if valid, false otherwise —
   never throws on malformed input."
  [pub-bytes message-bytes signature-bytes]
  (try
    (na/verify? pub-bytes message-bytes signature-bytes)
    (catch Exception _ false)))

(defn generate-x25519-keypair
  "Generate an X25519 keypair. Returns [public-key-bytes private-key-bytes]."
  []
  (let [priv (na/random-bytes 32)]
    [(na/x25519-base priv) priv]))

(defn x25519-private->public-key
  "Derive the X25519 public key (32 bytes) from a private key (32 bytes)."
  [priv-bytes]
  (na/x25519-base priv-bytes))

(defn ed25519-pub->x25519-pub
  "Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes)."
  [ed-pub]
  (na/ed-pk->x-pk ed-pub))

(defn ed25519-seed->x25519-private
  "Convert an Ed25519 seed (32 bytes) to an X25519 private key (32 bytes)."
  [seed]
  (na/ed-sk->x-sk (second (na/seed->keypair seed))))

(defn ed25519-keypair->x25519-keypair
  "Convert an Ed25519 keypair to an X25519 keypair.
   Returns [x25519-public-bytes x25519-private-bytes]."
  [ed-pub ed-seed]
  [(ed25519-pub->x25519-pub ed-pub) (ed25519-seed->x25519-private ed-seed)])

(defn x25519-dh
  "Perform X25519 Diffie-Hellman key agreement. Returns the 32-byte shared
   secret; throws for low-order points."
  [our-private their-public]
  (na/x25519 our-private their-public))

(defn hmac-sha-256
  "Compute HMAC-SHA-256(key, data). Returns 32 bytes."
  [key data]
  (na/hmac-sha256 key data))

(defn hkdf-sha-256
  "HKDF (RFC 5869) extract-then-expand. Returns `length` bytes derived
   from `ikm` with optional salt + info. salt and info default to empty."
  ([ikm length]
   (hkdf-sha-256 ikm (byte-array 0) (byte-array 0) length))
  ([ikm salt info length]
   (na/hkdf-sha256 ikm salt info length)))

(defn random-bytes
  "Cryptographically secure random byte array of length n."
  [n]
  (na/random-bytes n))

(defn chacha20-poly1305-encrypt
  "AEAD encrypt: ChaCha20-Poly1305(key=32B, nonce=12B, plaintext, aad).
   `aad` may be nil. Returns ciphertext || 16-byte tag."
  [key nonce plaintext aad]
  (na/aead-encrypt key nonce plaintext aad))

(defn chacha20-poly1305-decrypt
  "AEAD decrypt. Throws on auth failure or tampered AAD."
  [key nonce ciphertext aad]
  (na/aead-decrypt key nonce ciphertext aad))
