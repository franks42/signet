(ns signet.impl.jvm-secp256k1
  "BouncyCastle-backed secp256k1 ECDSA. JVM-only.

   This namespace does NOT load on babashka because BC is excluded
   from bb's SCI class allowlist. signet.sign / signet.key resolve
   these functions lazily via `requiring-resolve`, so the namespace is
   only loaded when a secp256k1 operation is actually invoked. On bb,
   that load fails with a clear ClassNotFoundException — which we wrap
   in a more informative exception at the call site.

   Wire conventions (matching threshold-signatures and the rest of
   signet's API):
     public key  — 33-byte sec1 compressed [parity_byte || x32]
     private key — 32-byte big-endian scalar
     signature   — 64-byte raw r||s on output;
                   verify accepts raw 64 OR DER (auto-detected)"
  (:import [java.math BigInteger]
           [java.security KeyFactory KeyPairGenerator Security Signature]
           [java.security.spec ECGenParameterSpec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.util Arrays]
           [org.bouncycastle.jce.provider BouncyCastleProvider]))

;; Install the BC provider on namespace load.
(defonce ^:private bc-installed
  (do (Security/addProvider (BouncyCastleProvider.))
      :installed))

;; ---------- byte-twiddling helpers ----------

(defn- pad-left
  "Big-endian pad/truncate a BigInteger to exactly n bytes."
  [^BigInteger n size]
  (let [be (.toByteArray n)
        be-len (alength be)
        ;; Strip leading sign byte if present.
        src-offset (if (and (> be-len size) (zero? (aget be 0))) 1 0)
        src-len (- be-len src-offset)
        out (byte-array size)
        dst-offset (max 0 (- size src-len))]
    (System/arraycopy be src-offset out dst-offset (min src-len size))
    out))

;; ---------- DER ↔ raw signature conversion ----------

(defn- raw->der-sig
  "Convert a 64-byte raw r||s ECDSA signature to DER. Adds the leading
   0x00 padding when the high bit of r or s is set (DER INTEGER is
   two's-complement and must not appear negative)."
  [^bytes raw]
  (when-not (= 64 (alength raw))
    (throw (ex-info "raw secp256k1 signature must be 64 bytes" {:length (alength raw)})))
  (let [strip-zeros (fn [^bytes bs]
                      (loop [i 0]
                        (cond
                          (>= i (alength bs)) (byte-array [(byte 0)])
                          (zero? (aget bs i)) (recur (inc i))
                          :else               (Arrays/copyOfRange bs i (alength bs)))))
        prefix-zero (fn [^bytes bs]
                      (if (neg? (aget bs 0))
                        (let [out (byte-array (inc (alength bs)))]
                          (System/arraycopy bs 0 out 1 (alength bs))
                          out)
                        bs))
        encode-int  (fn [^bytes scalar]
                      (-> scalar strip-zeros prefix-zero))
        r-enc (encode-int (Arrays/copyOfRange raw 0 32))
        s-enc (encode-int (Arrays/copyOfRange raw 32 64))
        seq-len (+ 2 (alength r-enc) 2 (alength s-enc))
        out (byte-array (+ 2 seq-len))]
    (aset-byte out 0 (unchecked-byte 0x30))
    (aset-byte out 1 (unchecked-byte seq-len))
    (aset-byte out 2 (unchecked-byte 0x02))
    (aset-byte out 3 (unchecked-byte (alength r-enc)))
    (System/arraycopy r-enc 0 out 4 (alength r-enc))
    (let [s-tag-pos (+ 4 (alength r-enc))]
      (aset-byte out s-tag-pos (unchecked-byte 0x02))
      (aset-byte out (inc s-tag-pos) (unchecked-byte (alength s-enc)))
      (System/arraycopy s-enc 0 out (+ 2 s-tag-pos) (alength s-enc)))
    out))

(defn- der->raw-sig
  "Convert a DER-encoded ECDSA signature to 64-byte raw r||s. Strips
   DER framing and any leading 0x00 padding, left-pads each scalar to
   32 bytes."
  [^bytes der]
  (let [n (alength der)]
    (when (< n 8)
      (throw (ex-info "DER signature too short" {:length n})))
    (when-not (= 0x30 (bit-and (aget der 0) 0xff))
      (throw (ex-info "DER signature must start with 0x30" {:first (aget der 0)})))
    (let [r-tag-pos 2
          _ (when-not (= 0x02 (bit-and (aget der r-tag-pos) 0xff))
              (throw (ex-info "Expected INTEGER tag for r" {:got (aget der r-tag-pos)})))
          r-len (bit-and (aget der (inc r-tag-pos)) 0xff)
          r-val-pos (+ r-tag-pos 2)
          r-bytes (Arrays/copyOfRange der r-val-pos (+ r-val-pos r-len))
          s-tag-pos (+ r-val-pos r-len)
          _ (when-not (= 0x02 (bit-and (aget der s-tag-pos) 0xff))
              (throw (ex-info "Expected INTEGER tag for s" {:got (aget der s-tag-pos)})))
          s-len (bit-and (aget der (inc s-tag-pos)) 0xff)
          s-val-pos (+ s-tag-pos 2)
          s-bytes (Arrays/copyOfRange der s-val-pos (+ s-val-pos s-len))
          r (BigInteger. 1 r-bytes)
          s (BigInteger. 1 s-bytes)
          out (byte-array 64)]
      (System/arraycopy (pad-left r 32) 0 out 0 32)
      (System/arraycopy (pad-left s 32) 0 out 32 32)
      out)))

(defn detect-sig-format
  "Heuristic on signature length + first byte:
   64 bytes ⇒ :raw; starts with 0x30 + plausible length ⇒ :der; else :unknown."
  [^bytes sig]
  (let [n (alength sig)]
    (cond
      (= n 64)
      :raw

      (and (>= n 8) (= 0x30 (bit-and (aget sig 0) 0xff)))
      :der

      :else
      :unknown)))

(defn- coerce-sig->der
  "Take a signature in either raw or DER form and return DER bytes."
  [^bytes sig]
  (case (detect-sig-format sig)
    :raw (raw->der-sig sig)
    :der sig
    (throw (ex-info "Unrecognized ECDSA signature format" {:length (alength sig)}))))

;; ---------- key reconstruction (PKCS8 / X.509 prefixes) ----------

;; PKCS#8 PrivateKeyInfo prefix for an EC private key on secp256k1
;; with a 32-byte scalar appended. Layout:
;;   30 3E                                            SEQUENCE (62 bytes)
;;     02 01 00                                       INTEGER (version 0)
;;     30 10 06 07 2A 86 48 CE 3D 02 01               AlgorithmIdentifier
;;            06 05 2B 81 04 00 0A                       ecPublicKey + secp256k1
;;     04 27                                          OCTET STRING (39 bytes)
;;       30 25 02 01 01                               ECPrivateKey SEQ + version 1
;;         04 20 <32 byte scalar>                     OCTET STRING
(def ^:private secp256k1-pkcs8-prefix
  (byte-array (map unchecked-byte
                   [0x30 0x3E 0x02 0x01 0x00
                    0x30 0x10
                    0x06 0x07 0x2A 0x86 0x48 0xCE 0x3D 0x02 0x01
                    0x06 0x05 0x2B 0x81 0x04 0x00 0x0A
                    0x04 0x27 0x30 0x25 0x02 0x01 0x01
                    0x04 0x20])))

;; X.509 SubjectPublicKeyInfo prefix for secp256k1 expecting a 33-byte
;; sec1-compressed point appended. BC's KeyFactory accepts compressed.
(def ^:private secp256k1-x509-compressed-prefix
  (byte-array (map unchecked-byte
                   [0x30 0x36 0x30 0x10
                    0x06 0x07 0x2A 0x86 0x48 0xCE 0x3D 0x02 0x01
                    0x06 0x05 0x2B 0x81 0x04 0x00 0x0A
                    0x03 0x22 0x00])))

(defn- compressed->jca-public
  [^bytes pub33]
  (when-not (= 33 (alength pub33))
    (throw (ex-info "secp256k1 compressed pubkey must be 33 bytes" {:length (alength pub33)})))
  (let [parity (bit-and (aget pub33 0) 0xff)
        _ (when-not (or (= 0x02 parity) (= 0x03 parity))
            (throw (ex-info "secp256k1 compressed pubkey first byte must be 0x02 or 0x03"
                            {:parity-byte parity})))
        prefix-len (alength secp256k1-x509-compressed-prefix)
        x509       (byte-array (+ prefix-len 33))
        _          (System/arraycopy secp256k1-x509-compressed-prefix 0 x509 0 prefix-len)
        _          (System/arraycopy pub33 0 x509 prefix-len 33)
        kf         (KeyFactory/getInstance "EC" "BC")]
    (.generatePublic kf (X509EncodedKeySpec. x509))))

(defn- scalar->jca-private
  [^bytes priv32]
  (when-not (= 32 (alength priv32))
    (throw (ex-info "secp256k1 scalar must be 32 bytes" {:length (alength priv32)})))
  (let [prefix-len (alength secp256k1-pkcs8-prefix)
        pkcs8      (byte-array (+ prefix-len 32))
        _          (System/arraycopy secp256k1-pkcs8-prefix 0 pkcs8 0 prefix-len)
        _          (System/arraycopy priv32 0 pkcs8 prefix-len 32)
        kf         (KeyFactory/getInstance "EC" "BC")]
    (.generatePrivate kf (PKCS8EncodedKeySpec. pkcs8))))

;; ---------- public API ----------

(defn generate-secp256k1-keypair
  "Generate a fresh secp256k1 ECDSA keypair via BouncyCastle.
   Returns [pub-bytes priv-bytes]:
     pub-bytes  — 33-byte sec1 compressed
     priv-bytes — 32-byte big-endian scalar"
  []
  (let [kpg (KeyPairGenerator/getInstance "EC" "BC")
        _ (.initialize kpg (ECGenParameterSpec. "secp256k1"))
        kp (.generateKeyPair kpg)
        pub (.getPublic kp)
        priv (.getPrivate kp)
        ;; BC's BCECPublicKey.getQ() returns an org.bouncycastle.math.ec.ECPoint
        ;; with .getEncoded(true) for compressed. Use reflection so we
        ;; don't have to :import BC-specific classes here.
        q-method (.getMethod (class pub) "getQ" (into-array Class []))
        q (.invoke q-method pub (into-array Object []))
        encoded-method (.getMethod (class q) "getEncoded" (into-array Class [Boolean/TYPE]))
        pub-bytes (.invoke encoded-method q (into-array Object [(Boolean/valueOf true)]))
        ;; BC's BCECPrivateKey.getD() returns a BigInteger.
        d-method (.getMethod (class priv) "getD" (into-array Class []))
        d (.invoke d-method priv (into-array Object []))
        priv-bytes (pad-left d 32)]
    [pub-bytes priv-bytes]))

(defn secp256k1-sign
  "Sign message bytes with a secp256k1 private scalar (32 bytes).
   Returns a 64-byte raw r||s signature."
  [^bytes priv-bytes ^bytes message-bytes]
  (let [priv-key (scalar->jca-private priv-bytes)
        signer (Signature/getInstance "SHA256withECDSA" "BC")]
    (.initSign signer priv-key)
    (.update signer message-bytes)
    (der->raw-sig (.sign signer))))

(defn secp256k1-verify
  "Verify a secp256k1 ECDSA signature. Accepts raw 64-byte r||s OR DER
   (auto-detected). Returns true if valid, false otherwise — never
   throws on malformed signature input."
  [^bytes pub-bytes ^bytes message-bytes ^bytes signature-bytes]
  (try
    (let [pub-key (compressed->jca-public pub-bytes)
          der-sig (coerce-sig->der signature-bytes)
          verifier (Signature/getInstance "SHA256withECDSA" "BC")]
      (.initVerify verifier pub-key)
      (.update verifier message-bytes)
      (.verify verifier der-sig))
    (catch Exception _ false)))
