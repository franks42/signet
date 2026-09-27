(ns ^:no-doc signet.impl.jvm
  "INTERNAL — not part of signet's public API. These functions take raw
   keys and caller-chosen AEAD nonces; misusing them (e.g. reusing a nonce)
   breaks confidentiality and integrity. Use signet.sign, signet.chain,
   signet.encryption and signet.session instead, which create and manage
   nonces and ephemeral keys internally. Public only because signet's own
   namespaces call them.

   JVM implementation of Ed25519/X25519 key operations using Java JCA.

   secp256k1 ECDSA lives in signet.impl.jvm-secp256k1 (JVM-only,
   BouncyCastle-backed). Kept separate so this namespace stays
   bb-compatible — bb's SCI class allowlist excludes BC."
  (:import [java.math BigInteger]
           [java.security KeyFactory KeyPairGenerator
            MessageDigest SecureRandom Signature]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.util Arrays]
           [javax.crypto KeyAgreement]))

(defn- extract-raw-keys
  "Extract raw key bytes from a JCA KeyPair.
   Returns [public-key-bytes private-key-bytes].
   Pure."
  [kp]
  (let [x509-bytes (.getEncoded (.getPublic kp))
        pub-bytes (Arrays/copyOfRange x509-bytes 12 44)
        pkcs8-bytes (.getEncoded (.getPrivate kp))
        priv-bytes (Arrays/copyOfRange pkcs8-bytes 16 48)]
    [pub-bytes priv-bytes]))

(defn- seed->keypair-via-kpg
  "Derive a JCA KeyPair from a seed by feeding it to KeyPairGenerator
   via a custom SecureRandom. Works for both Ed25519 and X25519.
   Pure (the fake SecureRandom returns only the copied seed)."
  [^String algorithm ^bytes seed-bytes]
  (let [seed-copy (byte-array seed-bytes)
        fake-random (proxy [SecureRandom] []
                      (nextBytes [^bytes bytes]
                        (System/arraycopy seed-copy 0 bytes 0
                                          (min (count bytes) (count seed-copy)))))
        kpg (KeyPairGenerator/getInstance algorithm)]
    (.initialize kpg (.newInstance
                      (.getConstructor
                       (Class/forName "java.security.spec.NamedParameterSpec")
                       (into-array Class [String]))
                      (into-array Object [algorithm]))
                 fake-random)
    (.generateKeyPair kpg)))

(defn generate-ed25519-keypair
  "Generate an Ed25519 keypair. Returns [public-key-bytes private-key-seed-bytes].
   Impure: draws from the CSPRNG."
  []
  (extract-raw-keys (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))))

(defn ed25519-seed->public-key
  "Derive the Ed25519 public key (32 bytes) from a seed (32 bytes).
   Pure."
  [seed-bytes]
  (let [[pub-bytes _] (extract-raw-keys (seed->keypair-via-kpg "Ed25519" seed-bytes))]
    pub-bytes))

(defn sha-256
  "Compute SHA-256 hash of byte array. Returns 32-byte hash.
   Pure."
  [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn ed25519-sign
  "Sign message bytes with an Ed25519 private key seed (32 bytes).
   Returns 64-byte signature.
   Pure (Ed25519 is deterministic)."
  [seed-bytes message-bytes]
  (let [;; Reconstruct PKCS#8 DER encoding from raw seed
        pkcs8-header (byte-array [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06
                                  0x03 0x2b 0x65 0x70 0x04 0x22 0x04 0x20])
        pkcs8-bytes (byte-array 48)
        _ (System/arraycopy pkcs8-header 0 pkcs8-bytes 0 16)
        _ (System/arraycopy seed-bytes 0 pkcs8-bytes 16 32)
        key-spec (java.security.spec.PKCS8EncodedKeySpec. pkcs8-bytes)
        kf (java.security.KeyFactory/getInstance "Ed25519")
        private-key (.generatePrivate kf key-spec)
        sig (Signature/getInstance "Ed25519")]
    (.initSign sig private-key)
    (.update sig ^bytes message-bytes)
    (.sign sig)))

(defn ed25519-verify
  "Verify an Ed25519 signature. Returns true if valid, false otherwise.

   Catches any JCA exception and returns false — a tampered bit can
   land on an invalid Ed25519 curve point, which JCA reports as
   SignatureException; verifying untrusted input must never crash.
   We catch the broadest Exception class here so this works both on
   JVM Clojure and under babashka's SCI (which doesn't have every
   java.security exception class in its built-in class list).
   Pure. Never throws: a malformed key or signature gives false."
  [pub-bytes message-bytes signature-bytes]
  (try
    (let [;; Reconstruct X.509 DER encoding from raw public key
          x509-header (byte-array [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65
                                   0x70 0x03 0x21 0x00])
          x509-bytes  (byte-array 44)
          _           (System/arraycopy x509-header 0 x509-bytes 0 12)
          _           (System/arraycopy pub-bytes 0 x509-bytes 12 32)
          key-spec    (java.security.spec.X509EncodedKeySpec. x509-bytes)
          kf          (java.security.KeyFactory/getInstance "Ed25519")
          public-key  (.generatePublic kf key-spec)
          sig         (Signature/getInstance "Ed25519")]
      (.initVerify sig public-key)
      (.update sig ^bytes message-bytes)
      (.verify sig ^bytes signature-bytes))
    (catch Exception _ false)))

(defn generate-x25519-keypair
  "Generate an X25519 keypair. Returns [public-key-bytes private-key-bytes].
   Impure: draws from the CSPRNG."
  []
  (extract-raw-keys (.generateKeyPair (KeyPairGenerator/getInstance "X25519"))))

(defn x25519-private->public-key
  "Derive the X25519 public key (32 bytes) from a private key (32 bytes).
   Pure."
  [priv-bytes]
  (let [[pub-bytes _] (extract-raw-keys (seed->keypair-via-kpg "X25519" priv-bytes))]
    pub-bytes))

;; -- Ed25519 <-> X25519 conversion
;;
;; Ed25519 uses the twisted Edwards curve, X25519 uses the Montgomery curve.
;; They are birationally equivalent (both are Curve25519).
;;
;; Private key: Ed25519 seed → SHA-512 → first 32 bytes = X25519 scalar
;; Public key:  Edwards point (y-coordinate) → Montgomery u-coordinate
;;              u = (1 + y) / (1 - y) mod p, where p = 2^255 - 19
;;
;; The reverse (X25519 → Ed25519) is NOT possible:
;; - SHA-512 is one-way (can't recover Ed25519 seed from X25519 scalar)
;; - Montgomery → Edwards has a sign ambiguity

(def ^:private ^BigInteger field-prime
  "The prime field for Curve25519: p = 2^255 - 19"
  (.subtract (.pow (BigInteger/valueOf 2) 255) (BigInteger/valueOf 19)))

(defn- le-bytes->bigint
  "Convert 32 little-endian bytes to a non-negative BigInteger.
   Pure."
  [^bytes bs]
  (let [be (byte-array 32)]
    (dotimes [i 32]
      (aset be i (aget bs (- 31 i))))
    (BigInteger. 1 be)))

(defn- bigint->le-bytes
  "Convert a non-negative BigInteger to 32 little-endian bytes.
   Pure."
  [^BigInteger n]
  (let [be (.toByteArray n)
        result (byte-array 32)
        ;; BigInteger.toByteArray may have leading sign byte or be shorter than 32
        be-len (alength be)
        ;; Skip leading sign byte if present (when high bit is set, BigInteger adds 0x00)
        src-offset (if (and (> be-len 32) (zero? (aget be 0))) 1 0)
        src-len (- be-len src-offset)
        dst-offset (- 32 (min src-len 32))]
    ;; Copy big-endian bytes into result, then reverse
    (System/arraycopy be src-offset result dst-offset (min src-len 32))
    ;; Reverse in-place → little-endian
    (dotimes [i 16]
      (let [j (- 31 i)
            tmp (aget result i)]
        (aset result i (aget result j))
        (aset result j tmp)))
    result))

;; -- Ed25519 point validation, as libsodium's
;;    crypto_sign_ed25519_pk_to_curve25519 does it, so that both backends
;;    accept and refuse exactly the same public keys: the point must decode
;;    onto the curve, must not have small order, and must be in the
;;    prime-order subgroup (L * P = identity).

(defn- fmul ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.multiply a b) field-prime))
(defn- fadd ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.add a b) field-prime))
(defn- fsub ^BigInteger [^BigInteger a ^BigInteger b] (.mod (.subtract a b) field-prime))

(def ^:private ^BigInteger ed-d
  "The Edwards curve constant d = -121665/121666 mod p."
  (fmul (.mod (BigInteger/valueOf -121665) field-prime)
        (.modInverse (BigInteger/valueOf 121666) field-prime)))

(def ^:private ^BigInteger ed-2d (fadd ed-d ed-d))

(def ^:private ^BigInteger sqrt-m1
  "A square root of -1 mod p: 2^((p-1)/4)."
  (.modPow (BigInteger/valueOf 2) (.divide (.subtract field-prime BigInteger/ONE) (BigInteger/valueOf 4))
           field-prime))

(def ^:private ^BigInteger group-order
  "L = 2^252 + 27742317777372353535851937790883648493."
  (.add (.shiftLeft BigInteger/ONE 252) (BigInteger. "27742317777372353535851937790883648493")))

(defn- decode-point
  "[x y] of the Ed25519 point that 32-byte encoding bs names, or nil if it
   is not on the curve. The sign bit is ignored (x or -x: the checks below
   do not depend on it), and y is reduced mod p, as libsodium does.
   Pure."
  [^bytes bs]
  (let [yb (byte-array bs)
        _  (aset yb 31 (unchecked-byte (bit-and (aget yb 31) 0x7f)))
        y  (.mod (le-bytes->bigint yb) field-prime)
        yy (fmul y y)
        u  (fsub yy BigInteger/ONE)                   ; y^2 - 1
        v  (fadd (fmul ed-d yy) BigInteger/ONE)       ; d y^2 + 1 (never 0)
        x2 (fmul u (.modInverse v field-prime))
        r  (.modPow x2 (.divide (.add field-prime (BigInteger/valueOf 3)) (BigInteger/valueOf 8)) field-prime)]
    (cond
      (= (fmul r r) x2)                    [r y]
      (= (fmul r r) (fsub BigInteger/ZERO x2)) [(fmul r sqrt-m1) y]
      :else                                nil)))

(defn- small-order?
  "Does point [x y] have small order (x = 0, y = 0, or y*sqrt(-1) = +-x)?
   Pure."
  [[^BigInteger x ^BigInteger y]]
  (let [ys (fmul y sqrt-m1)]
    (or (zero? (.signum x)) (zero? (.signum y))
        (= ys x) (= ys (fsub BigInteger/ZERO x)))))

(defn- ext-add
  "Sum of two points in extended coordinates [X Y Z T] (a = -1): the
   add-2008-hwcd-3 formula, complete on this curve, so it also doubles.
   Pure."
  [[x1 y1 z1 t1] [x2 y2 z2 t2]]
  (let [a (fmul (fsub y1 x1) (fsub y2 x2))
        b (fmul (fadd y1 x1) (fadd y2 x2))
        c (fmul (fmul t1 ed-2d) t2)
        d (fmul (fadd z1 z1) z2)
        e (fsub b a) f (fsub d c) g (fadd d c) h (fadd b a)]
    [(fmul e f) (fmul g h) (fmul f g) (fmul e h)]))

(defn- in-prime-subgroup?
  "Is L * [x y] the identity? Pure."
  [[x y]]
  (let [p [x y BigInteger/ONE (fmul x y)]
        [rx ry rz] (reduce (fn [r i]
                             (let [r2 (ext-add r r)]
                               (if (.testBit ^BigInteger group-order i) (ext-add r2 p) r2)))
                           [BigInteger/ZERO BigInteger/ONE BigInteger/ONE BigInteger/ZERO]
                           (range (dec (.bitLength ^BigInteger group-order)) -1 -1))]
    (and (zero? (.signum ^BigInteger rx)) (= ry rz))))

(defn ed25519-pub->x25519-pub
  "Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes).
   Uses the birational map: u = (1 + y) / (1 - y) mod p.
   Pure.
   Throws ex-info {:type :signet.impl/invalid-public-key} for a point that
   is not on the curve, has small order, or is outside the prime-order
   subgroup: the same keys libsodium refuses."
  [^bytes ed-pub]
  (let [pt (decode-point ed-pub)
        _  (when-not (and pt (not (small-order? pt)) (in-prime-subgroup? pt))
             (throw (ex-info "Not a valid Ed25519 public key"
                             {:type :signet.impl/invalid-public-key})))
        y  (second pt)
        ;; u = (1 + y) * (1 - y)^(-1) mod p
        one BigInteger/ONE
        p field-prime
        numerator (.mod (.add one y) p)
        denominator (.mod (.subtract one y) p)
        denom-inv (.modInverse denominator p)
        u (.mod (.multiply numerator denom-inv) p)]
    (bigint->le-bytes u)))

(defn ed25519-seed->x25519-private
  "Convert an Ed25519 seed (32 bytes) to an X25519 private key (32 bytes).
   Applies SHA-512 to the seed, takes the first 32 bytes, and clamps.
   Pure."
  [^bytes seed]
  (let [md (MessageDigest/getInstance "SHA-512")
        h (.digest md seed)
        x-priv (Arrays/copyOf h 32)]
    ;; Clamp per RFC 7748
    (aset x-priv 0  (unchecked-byte (bit-and (aget x-priv 0)  0xf8)))
    (aset x-priv 31 (unchecked-byte (bit-and (aget x-priv 31) 0x7f)))
    (aset x-priv 31 (unchecked-byte (bit-or  (aget x-priv 31) 0x40)))
    x-priv))

(defn ed25519-keypair->x25519-keypair
  "Convert an Ed25519 keypair to an X25519 keypair.
   Returns [x25519-public-bytes x25519-private-bytes].
   Pure."
  [^bytes ed-pub ^bytes ed-seed]
  (let [x-priv (ed25519-seed->x25519-private ed-seed)
        x-pub (ed25519-pub->x25519-pub ed-pub)]
    [x-pub x-priv]))

;; -- X25519 Diffie-Hellman key agreement

(defn- x25519-raw->jca-private
  "Reconstruct a JCA X25519 PrivateKey from raw 32 bytes.
   Pure."
  [^bytes priv-bytes]
  (let [pkcs8-header (byte-array [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06
                                  0x03 0x2b 0x65 0x6e 0x04 0x22 0x04 0x20])
        pkcs8 (byte-array 48)
        _ (System/arraycopy pkcs8-header 0 pkcs8 0 16)
        _ (System/arraycopy priv-bytes 0 pkcs8 16 32)
        kf (KeyFactory/getInstance "X25519")]
    (.generatePrivate kf (PKCS8EncodedKeySpec. pkcs8))))

(defn- x25519-raw->jca-public
  "Reconstruct a JCA X25519 PublicKey from raw 32 bytes.
   Pure."
  [^bytes pub-bytes]
  (let [x509-header (byte-array [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65
                                 0x6e 0x03 0x21 0x00])
        x509 (byte-array 44)
        _ (System/arraycopy x509-header 0 x509 0 12)
        _ (System/arraycopy pub-bytes 0 x509 12 32)
        kf (KeyFactory/getInstance "X25519")]
    (.generatePublic kf (X509EncodedKeySpec. x509))))

(defn x25519-dh
  "Perform X25519 Diffie-Hellman key agreement.
   Returns the 32-byte shared secret.
   Pure.
   Throws ex-info {:type :signet.impl/low-order-point} when the result is
   all zeros (their key has small order), as the libsodium backend does."
  [^bytes our-private ^bytes their-public]
  (let [priv-key (x25519-raw->jca-private our-private)
        pub-key (x25519-raw->jca-public their-public)
        ka (KeyAgreement/getInstance "X25519")]
    (.init ka priv-key)
    (try
      (.doPhase ka pub-key true)
      (let [out (.generateSecret ka)]
        (when (every? zero? out)
          (throw (ex-info "X25519 with a low-order public key" {:type :signet.impl/low-order-point})))
        out)
      (catch Exception e
        ;; JCA refuses a small-order point itself with an InvalidKeyException
        ;; (matched by name: babashka does not expose that class)
        (if (= "java.security.InvalidKeyException" (.getName (class e)))
          (throw (ex-info "X25519 with a low-order public key"
                          {:type :signet.impl/low-order-point} e))
          (throw e))))))

;; ============================================================
;; AEAD primitives: HKDF-SHA-256 + ChaCha20-Poly1305 via JCA
;; ============================================================
;;
;; Used by signet.encryption for sender-authenticated pubkey-to-pubkey
;; encryption. JCA-only; bb-compatible (no BouncyCastle needed for
;; symmetric primitives).

(defn hmac-sha-256
  "Compute HMAC-SHA-256(key, data). Returns 32 bytes.
   Pure."
  [^bytes key ^bytes data]
  (let [mac      (javax.crypto.Mac/getInstance "HmacSHA256")
        key-spec (javax.crypto.spec.SecretKeySpec. key "HmacSHA256")]
    (.init mac key-spec)
    (.doFinal mac data)))

(defn hkdf-sha-256
  "HKDF (RFC 5869) extract-then-expand. Returns `length` bytes derived
   from `ikm` with optional salt + info. salt and info default to empty.
   Pure.
   Throws ex-info {:type :signet.impl/bad-length} unless length is 1..8160."
  ([^bytes ikm length]
   (hkdf-sha-256 ikm (byte-array 0) (byte-array 0) length))
  ([^bytes ikm ^bytes salt ^bytes info length]
   ;; RFC 5869: at most 255 blocks; the one-byte counter wraps beyond that
   (when-not (and (integer? length) (<= 1 length 8160))
     (throw (ex-info "HKDF-SHA-256 output length must be 1..8160"
                     {:type :signet.impl/bad-length :length length})))
   (let [;; Extract: PRK = HMAC(salt, ikm)
         salt' (if (zero? (alength salt)) (byte-array 32) salt)
         prk   (hmac-sha-256 salt' ikm)
         ;; Expand: T(i) = HMAC(PRK, T(i-1) || info || byte(i))
         out   (byte-array length)]
     (loop [i      1
            prev   (byte-array 0)
            offset 0]
       (when (< offset length)
         (let [data    (byte-array (+ (alength prev) (alength info) 1))
               _       (System/arraycopy prev 0 data 0 (alength prev))
               _       (System/arraycopy info 0 data (alength prev) (alength info))
               _       (aset-byte data (dec (alength data)) (unchecked-byte i))
               t       (hmac-sha-256 prk data)
               n       (min (alength t) (- length offset))]
           (System/arraycopy t 0 out offset n)
           (recur (inc i) t (+ offset n)))))
     out)))

(defn random-bytes
  "Cryptographically secure random byte array of length n.
   Impure: draws from the CSPRNG."
  [n]
  (let [bs  (byte-array n)
        rng (java.security.SecureRandom.)]
    (.nextBytes rng bs)
    bs))

(defn chacha20-poly1305-encrypt
  "AEAD encrypt: ChaCha20-Poly1305(key=32B, nonce=12B, plaintext, aad).
   `aad` may be nil. Returns ciphertext || 16-byte tag.
   Pure."
  [^bytes key ^bytes nonce ^bytes plaintext aad]
  (let [cipher    (javax.crypto.Cipher/getInstance "ChaCha20-Poly1305")
        key-spec  (javax.crypto.spec.SecretKeySpec. key "ChaCha20")
        iv-spec   (javax.crypto.spec.IvParameterSpec. nonce)]
    (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec iv-spec)
    (when aad (.updateAAD cipher ^bytes aad))
    (.doFinal cipher plaintext)))

(defn chacha20-poly1305-decrypt
  "AEAD decrypt. `ciphertext` is the output of chacha20-poly1305-encrypt
   (i.e. ciphertext || tag). Throws on auth failure or tampered AAD.
   Pure."
  [^bytes key ^bytes nonce ^bytes ciphertext aad]
  (let [cipher    (javax.crypto.Cipher/getInstance "ChaCha20-Poly1305")
        key-spec  (javax.crypto.spec.SecretKeySpec. key "ChaCha20")
        iv-spec   (javax.crypto.spec.IvParameterSpec. nonce)]
    (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec iv-spec)
    (when aad (.updateAAD cipher ^bytes aad))
    (.doFinal cipher ciphertext)))

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
  "Split secret material m (a byte array) into new byte arrays of the given
   lengths, in order. m is left unchanged: destroy it when done.
   Throws ex-info {:type :signet.impl/bad-split} unless the lengths add up
   to m's size.
   Pure."
  [m lengths]
  (split-bytes m lengths))

(defn wrap-material
  "ChaCha20-Poly1305 of secret material m (bytes) under key k with a
   12-byte nonce and aad (nil for none). Returns ciphertext || tag. Pure."
  [k nonce m aad]
  (chacha20-poly1305-encrypt k nonce m aad))

(defn unwrap-material
  "Inverse of wrap-material: the material, as bytes. Pure.
   Throws ex-info {:type :signet.impl/auth-failed} when authentication
   fails."
  [k nonce ct aad]
  (try (chacha20-poly1305-decrypt k nonce ct aad)
       (catch Exception _
         (throw (ex-info "Authentication failed" {:type :signet.impl/auth-failed})))))

(defn argon2id
  "Argon2id is not in the JDK: password features need the libsodium
   backend. Never returns.
   Throws ex-info {:type :signet.impl/unsupported}."
  [_password _salt _len _limits]
  (throw (ex-info "Argon2id (password keys) needs signet's libsodium backend (-Dsignet.backend=sodium)"
                  {:type :signet.impl/unsupported :feature :argon2id})))

(defn argon2id-limits
  "Argon2id is not in the JDK: password features need the libsodium
   backend. Never returns.
   Throws ex-info {:type :signet.impl/unsupported}."
  [_preset]
  (throw (ex-info "Argon2id (password keys) needs signet's libsodium backend (-Dsignet.backend=sodium)"
                  {:type :signet.impl/unsupported :feature :argon2id})))

(defn destroy-material!
  "Release secret material whose purpose has ended: overwrite a byte array
   with zeros. (The JCA backend only ever handles byte arrays.) Impure:
   writes its argument. Returns nil."
  [x]
  (when (bytes? x) (java.util.Arrays/fill ^bytes x (byte 0)))
  nil)

