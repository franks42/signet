(ns ^:no-doc signet.impl.sodium
  "INTERNAL — not part of signet's public API. These functions take raw
   keys and caller-chosen AEAD nonces; misusing them (e.g. reusing a nonce)
   breaks confidentiality and integrity. Use signet.sign, signet.chain,
   signet.encryption and signet.session instead, which create and manage
   nonces and ephemeral keys internally. Public only because signet's own
   namespaces call them.

   libsodium backend for signet, via nacljc.core (babashka.ffi): the same
   16 functions and contracts as signet.impl.jvm (JCA). Selected through
   signet.impl; do not require directly.

   Requirements: libsodium >= 1.0.19 installed (e.g. brew install
   libsodium), nacljc on the classpath (deps.edn alias :sodium), JDK 25+
   with --enable-native-access=ALL-UNNAMED on the JVM, bb >= 1.13.220.

   Differences from the JCA backend:
   - Seed -> public key uses crypto_sign_seed_keypair instead of the JCA
     'fake SecureRandom' trick, so it also works on babashka.
   - nacljc.core type- and length-checks every input (a wrong one throws
     ex-info where JCA threw its own exception types) and wipes every native
     buffer before releasing it.
   - Ed25519 signs from the 32-byte seed: the 64-byte libsodium secret key
     exists only in native memory, never on the Clojure heap.
   - Output is byte-identical to the JCA backend (see
     test/signet/backend_parity.clj)."
  (:require [nacljc.core :as na]))

(def backend
  "This backend's name, as selected in signet.impl."
  :sodium)

(defn generate-ed25519-keypair
  "Generate an Ed25519 keypair. Returns [public-key-bytes private-key-seed-bytes]."
  []
  (let [seed (na/random-bytes 32)
        pk   (na/ed25519-public-key seed)]
    [pk seed]))

(defn ed25519-seed->public-key
  "Derive the Ed25519 public key (32 bytes) from a seed (32 bytes)."
  [seed-bytes]
  (na/ed25519-public-key seed-bytes))

(defn sha-256
  "Compute SHA-256 hash of byte array. Returns 32-byte hash."
  [bs]
  (na/sha-256 bs))

(defn ed25519-sign
  "Sign message bytes with an Ed25519 private key seed (32 bytes).
   Returns 64-byte signature."
  [seed-bytes message-bytes]
  (na/ed25519-sign seed-bytes message-bytes))

(defn ed25519-verify
  "Verify an Ed25519 signature. Returns true if valid, false otherwise —
   never throws on malformed input."
  [pub-bytes message-bytes signature-bytes]
  (try
    (na/ed25519-verify? pub-bytes message-bytes signature-bytes)
    (catch Exception _ false)))

(defn generate-x25519-keypair
  "Generate an X25519 keypair. Returns [public-key-bytes private-key-bytes]."
  []
  (let [priv (na/random-bytes 32)]
    [(na/x25519-public-key priv) priv]))

(defn x25519-private->public-key
  "Derive the X25519 public key (32 bytes) from a private key (32 bytes)."
  [priv-bytes]
  (na/x25519-public-key priv-bytes))

(defn ed25519-pub->x25519-pub
  "Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes)."
  [ed-pub]
  (na/ed25519->x25519-public-key ed-pub))

(defn ed25519-seed->x25519-private
  "Convert an Ed25519 seed (32 bytes) to an X25519 private key (32 bytes)."
  [seed]
  (na/ed25519->x25519-secret-key seed))

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
  (na/hmac-sha-256 key data))

(defn hkdf-sha-256
  "HKDF (RFC 5869) extract-then-expand. Returns `length` bytes derived
   from `ikm` with optional salt + info. salt and info default to empty."
  ([ikm length]
   (hkdf-sha-256 ikm (byte-array 0) (byte-array 0) length))
  ([ikm salt info length]
   (na/hkdf-sha-256 ikm salt info length)))

(defn random-bytes
  "Cryptographically secure random byte array of length n."
  [n]
  (na/random-bytes n))

(defn chacha20-poly1305-encrypt
  "AEAD encrypt: ChaCha20-Poly1305(key=32B, nonce=12B, plaintext, aad).
   `aad` may be nil. Returns ciphertext || 16-byte tag."
  [key nonce plaintext aad]
  (na/chacha20-poly1305-encrypt key nonce plaintext aad))

(defn chacha20-poly1305-decrypt
  "AEAD decrypt. Throws on auth failure or tampered AAD."
  [key nonce ciphertext aad]
  (na/chacha20-poly1305-decrypt key nonce ciphertext aad))
