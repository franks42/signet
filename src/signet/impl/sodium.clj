(ns ^:no-doc signet.impl.sodium
  "INTERNAL — not part of signet's public API. These functions take raw
   keys and caller-chosen AEAD nonces; misusing them (e.g. reusing a nonce)
   breaks confidentiality and integrity. Use signet.sign, signet.chain,
   signet.encryption and signet.session instead, which create and manage
   nonces and ephemeral keys internally. Public only because signet's own
   namespaces call them.

   libsodium backend for signet, via nacljc.core (babashka.ffi): the same
   22 functions and contracts as signet.impl.jvm (JCA). Selected through
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
  "Generate an Ed25519 keypair. Returns [public-key-bytes private-key-seed-bytes].
   Impure: draws from the CSPRNG."
  []
  (let [seed (na/random-bytes 32)
        pk   (na/ed25519-public-key seed)]
    [pk seed]))

(defn ed25519-seed->public-key
  "Derive the Ed25519 public key (32 bytes) from a seed (32 bytes).
   Pure for a byte-array seed; with a nacljc secret, impure: reads it."
  [seed-bytes]
  (na/ed25519-public-key seed-bytes))

(defn sha-256
  "Compute SHA-256 hash of byte array. Returns 32-byte hash.
   Pure."
  [bs]
  (na/sha-256 bs))

(defn ed25519-sign
  "Sign message bytes with an Ed25519 private key seed (32 bytes).
   Returns 64-byte signature.
   Pure for a byte-array seed; with a nacljc secret, impure: reads it."
  [seed-bytes message-bytes]
  (na/ed25519-sign seed-bytes message-bytes))

(defn ed25519-verify
  "Verify an Ed25519 signature. Returns true if valid, false otherwise —
   never throws on malformed input.
   Pure. Never throws: a malformed key or signature gives false."
  [pub-bytes message-bytes signature-bytes]
  (try
    (na/ed25519-verify? pub-bytes message-bytes signature-bytes)
    (catch Exception _ false)))

(defn generate-x25519-keypair
  "Generate an X25519 keypair. Returns [public-key-bytes private-key-bytes].
   Impure: draws from the CSPRNG."
  []
  (let [priv (na/random-bytes 32)]
    [(na/x25519-public-key priv) priv]))

(defn x25519-private->public-key
  "Derive the X25519 public key (32 bytes) from a private key (32 bytes).
   Pure for a byte-array key; with a nacljc secret, impure: reads it."
  [priv-bytes]
  (na/x25519-public-key priv-bytes))

(defn ed25519-pub->x25519-pub
  "Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes).
   Pure.
   Throws ex-info {:type :signet.impl/invalid-public-key} for a point that
   is not on the curve, has small order, or is outside the prime-order
   subgroup (the same type the JCA backend throws)."
  [ed-pub]
  (try (na/ed25519->x25519-public-key ed-pub)
       (catch clojure.lang.ExceptionInfo e
         (if (= :nacljc.core/invalid-public-key (:type (ex-data e)))
           (throw (ex-info "Not a valid Ed25519 public key"
                           {:type :signet.impl/invalid-public-key} e))
           (throw e)))))

(defn ed25519-seed->x25519-private
  "Convert an Ed25519 seed (32 bytes) to an X25519 private key (32 bytes).
   Pure for a byte-array seed; with a nacljc secret, impure: reads it
   and allocates guarded memory for the secret result."
  [seed]
  (na/ed25519->x25519-secret-key seed))

(defn ed25519-keypair->x25519-keypair
  "Convert an Ed25519 keypair to an X25519 keypair.
   Returns [x25519-public-bytes x25519-private-bytes].
   Pure for byte arrays; with a nacljc secret, impure: as
   ed25519-seed->x25519-private."
  [ed-pub ed-seed]
  [(ed25519-pub->x25519-pub ed-pub) (ed25519-seed->x25519-private ed-seed)])

(defn x25519-dh
  "Perform X25519 Diffie-Hellman key agreement. Returns the 32-byte shared
   secret; throws for low-order points.
   Pure for a byte-array key; with a nacljc secret, impure: reads it and
   allocates guarded memory for the secret result.
   Throws ex-info {:type :signet.impl/low-order-point} for a low-order key
   (the same type the JCA backend throws)."
  [our-private their-public]
  (try (na/x25519 our-private their-public)
       (catch clojure.lang.ExceptionInfo e
         (if (= :nacljc.core/low-order-point (:type (ex-data e)))
           (throw (ex-info "X25519 with a low-order public key"
                           {:type :signet.impl/low-order-point} e))
           (throw e)))))

(defn hmac-sha-256
  "Compute HMAC-SHA-256(key, data). Returns 32 bytes.
   Pure for a byte-array key; with a nacljc secret, impure: reads it."
  [key data]
  (na/hmac-sha-256 key data))

(defn hkdf-sha-256
  "HKDF (RFC 5869) extract-then-expand. Returns `length` bytes derived
   from `ikm` with optional salt + info. salt and info default to empty.
   Pure for byte arrays; with a nacljc secret (ikm or salt), impure: reads
   it and allocates guarded memory for the secret result."
  ([ikm length]
   (hkdf-sha-256 ikm (byte-array 0) (byte-array 0) length))
  ([ikm salt info length]
   (na/hkdf-sha-256 ikm salt info length)))

(defn random-bytes
  "Cryptographically secure random byte array of length n.
   Impure: draws from the CSPRNG."
  [n]
  (na/random-bytes n))

(defn chacha20-poly1305-encrypt
  "AEAD encrypt: ChaCha20-Poly1305(key=32B, nonce=12B, plaintext, aad).
   `aad` may be nil. Returns ciphertext || 16-byte tag.
   Pure for a byte-array key; with a nacljc secret, impure: reads it."
  [key nonce plaintext aad]
  (na/chacha20-poly1305-encrypt key nonce plaintext aad))

(defn chacha20-poly1305-decrypt
  "AEAD decrypt. Throws on auth failure or tampered AAD.
   Pure for a byte-array key; with a nacljc secret, impure: reads it."
  [key nonce ciphertext aad]
  (na/chacha20-poly1305-decrypt key nonce ciphertext aad))

(defn- split-bytes
  "Pure.
   Throws ex-info {:type :signet.impl/bad-split} unless the lengths add up
   to m's size."
  [^bytes m lengths]
  (when-not (= (alength m) (reduce + lengths))
    (throw (ex-info "split-material: lengths must add up to the material's size"
                    {:type :signet.impl/bad-split :size (alength m) :lengths (vec lengths)})))
  (mapv (fn [off n] (java.util.Arrays/copyOfRange m (int off) (int (+ off n))))
        (reductions + 0 lengths) lengths))

(defn split-material
  "Split secret material m into parts of the given lengths, in order: a
   byte array into byte arrays, a nacljc secret into nacljc secrets (copied
   inside guarded memory). m is left unchanged: destroy it when done.
   Throws ex-info {:type :signet.impl/bad-split} (bytes) or nacljc's
   ::bad-length (secrets) unless the lengths add up to m's size.
   Pure for byte arrays; with a nacljc secret, impure: reads it and
   allocates guarded memory for the parts."
  [m lengths]
  (if (na/secret? m) (na/secret-split m lengths) (split-bytes m lengths)))

(defn wrap-material
  "ChaCha20-Poly1305 of secret material m under key k (bytes or a nacljc
   secret) with a 12-byte nonce and aad (nil for none). A nacljc secret m
   is read in place (wrap-secret): its bytes never reach the heap. Returns
   ciphertext || tag, safe to store.
   Impure: reads m and k when they are secrets. Pure for byte arrays."
  [k nonce m aad]
  (if (na/secret? m)
    (na/wrap-secret k nonce m aad)
    (na/chacha20-poly1305-encrypt k nonce m aad)))

(defn unwrap-material
  "Inverse of wrap-material. The result follows the key: with a nacljc
   secret k it is a new nacljc secret (unwrap-secret: the plaintext never
   exists as a byte array), with a byte-array k a byte array.
   Impure: reads k when it is a secret and allocates guarded memory for the
   result. Pure for byte arrays.
   Throws ex-info {:type :signet.impl/auth-failed} when authentication
   fails, and nacljc's errors for malformed inputs."
  [k nonce ct aad]
  (try
    (if (na/secret? k)
      (na/unwrap-secret k nonce ct aad)
      (na/chacha20-poly1305-decrypt k nonce ct aad))
    (catch clojure.lang.ExceptionInfo e
      (if (= :nacljc.core/auth-failed (:type (ex-data e)))
        (throw (ex-info "Authentication failed" {:type :signet.impl/auth-failed}))
        (throw e)))))

(defn argon2id
  "Argon2id (libsodium's crypto_pwhash, v1.3): len bytes from password (a
   byte array or a nacljc secret) and a 16-byte salt at the cost in limits
   {:opslimit n :memlimit bytes}. A secret password gives a secret result.
   Pure for a byte-array password; with a nacljc secret, impure: reads it
   and allocates guarded memory for the result.
   Throws nacljc's errors (::bad-input, ::bad-length, ::call-failed)."
  [password salt len limits]
  (na/argon2id password salt len limits))

(defn argon2id-limits
  "libsodium's Argon2id cost preset (:interactive, :moderate, :sensitive)
   as {:opslimit n :memlimit bytes}. Pure.
   Throws nacljc's ::bad-input for another preset."
  [preset]
  (na/argon2id-limits preset))

(defn destroy-material!
  "Release secret material whose purpose has ended: overwrite a byte array
   with zeros, or destroy a nacljc secret (zeroes and frees its guarded
   memory). Under the vault's :sodium provider, derived secrets (DH
   outputs, message keys) are nacljc secrets. Impure: writes or frees its
   argument. Returns nil."
  [x]
  (cond
    (bytes? x)      (java.util.Arrays/fill ^bytes x (byte 0))
    (na/secret? x)  (na/secret-destroy! x))
  nil)

