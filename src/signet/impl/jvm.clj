(ns signet.impl.jvm
  "JVM implementation of Ed25519/X25519 key operations using Java JCA."
  (:import [java.math BigInteger]
           [java.security KeyFactory KeyPairGenerator MessageDigest SecureRandom Signature]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.util Arrays]
           [javax.crypto KeyAgreement]))

(defn- extract-raw-keys
  "Extract raw key bytes from a JCA KeyPair.
   Returns [public-key-bytes private-key-bytes]."
  [kp]
  (let [x509-bytes (.getEncoded (.getPublic kp))
        pub-bytes (Arrays/copyOfRange x509-bytes 12 44)
        pkcs8-bytes (.getEncoded (.getPrivate kp))
        priv-bytes (Arrays/copyOfRange pkcs8-bytes 16 48)]
    [pub-bytes priv-bytes]))

(defn- seed->keypair-via-kpg
  "Derive a JCA KeyPair from a seed by feeding it to KeyPairGenerator
   via a custom SecureRandom. Works for both Ed25519 and X25519."
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
  "Generate an Ed25519 keypair. Returns [public-key-bytes private-key-seed-bytes]."
  []
  (extract-raw-keys (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))))

(defn ed25519-seed->public-key
  "Derive the Ed25519 public key (32 bytes) from a seed (32 bytes)."
  [seed-bytes]
  (let [[pub-bytes _] (extract-raw-keys (seed->keypair-via-kpg "Ed25519" seed-bytes))]
    pub-bytes))

(defn sha-256
  "Compute SHA-256 hash of byte array. Returns 32-byte hash."
  [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn ed25519-sign
  "Sign message bytes with an Ed25519 private key seed (32 bytes).
   Returns 64-byte signature."
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
  "Verify an Ed25519 signature. Returns true if valid."
  [pub-bytes message-bytes signature-bytes]
  (let [;; Reconstruct X.509 DER encoding from raw public key
        x509-header (byte-array [0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65
                                 0x70 0x03 0x21 0x00])
        x509-bytes (byte-array 44)
        _ (System/arraycopy x509-header 0 x509-bytes 0 12)
        _ (System/arraycopy pub-bytes 0 x509-bytes 12 32)
        key-spec (java.security.spec.X509EncodedKeySpec. x509-bytes)
        kf (java.security.KeyFactory/getInstance "Ed25519")
        public-key (.generatePublic kf key-spec)
        sig (Signature/getInstance "Ed25519")]
    (.initVerify sig public-key)
    (.update sig ^bytes message-bytes)
    (.verify sig ^bytes signature-bytes)))

(defn generate-x25519-keypair
  "Generate an X25519 keypair. Returns [public-key-bytes private-key-bytes]."
  []
  (extract-raw-keys (.generateKeyPair (KeyPairGenerator/getInstance "X25519"))))

(defn x25519-private->public-key
  "Derive the X25519 public key (32 bytes) from a private key (32 bytes)."
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
  "Convert 32 little-endian bytes to a non-negative BigInteger."
  [^bytes bs]
  (let [be (byte-array 32)]
    (dotimes [i 32]
      (aset be i (aget bs (- 31 i))))
    (BigInteger. 1 be)))

(defn- bigint->le-bytes
  "Convert a non-negative BigInteger to 32 little-endian bytes."
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

(defn ed25519-pub->x25519-pub
  "Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes).
   Uses the birational map: u = (1 + y) / (1 - y) mod p."
  [^bytes ed-pub]
  (let [;; Ed25519 public key encoding: y-coordinate in bits 0-254 (little-endian),
        ;; sign of x in bit 255. Clear the sign bit to get y.
        y-bytes (byte-array ed-pub)
        _ (aset y-bytes 31 (unchecked-byte (bit-and (aget y-bytes 31) 0x7f)))
        y (le-bytes->bigint y-bytes)
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
   Applies SHA-512 to the seed, takes the first 32 bytes, and clamps."
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
   Returns [x25519-public-bytes x25519-private-bytes]."
  [^bytes ed-pub ^bytes ed-seed]
  (let [x-priv (ed25519-seed->x25519-private ed-seed)
        x-pub (ed25519-pub->x25519-pub ed-pub)]
    [x-pub x-priv]))

;; -- X25519 Diffie-Hellman key agreement

(defn- x25519-raw->jca-private
  "Reconstruct a JCA X25519 PrivateKey from raw 32 bytes."
  [^bytes priv-bytes]
  (let [pkcs8-header (byte-array [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06
                                  0x03 0x2b 0x65 0x6e 0x04 0x22 0x04 0x20])
        pkcs8 (byte-array 48)
        _ (System/arraycopy pkcs8-header 0 pkcs8 0 16)
        _ (System/arraycopy priv-bytes 0 pkcs8 16 32)
        kf (KeyFactory/getInstance "X25519")]
    (.generatePrivate kf (PKCS8EncodedKeySpec. pkcs8))))

(defn- x25519-raw->jca-public
  "Reconstruct a JCA X25519 PublicKey from raw 32 bytes."
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
   Returns the 32-byte shared secret."
  [^bytes our-private ^bytes their-public]
  (let [priv-key (x25519-raw->jca-private our-private)
        pub-key (x25519-raw->jca-public their-public)
        ka (KeyAgreement/getInstance "X25519")]
    (.init ka priv-key)
    (.doPhase ka pub-key true)
    (.generateSecret ka)))
