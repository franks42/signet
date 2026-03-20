# Design Ideas for signet

## Core Philosophy

1. **Portable first**: cljc with reader conditionals for platform-specific backends
2. **Minimal dependencies**: Java JCA on JVM, WebCrypto + @noble/curves fallback on JS
3. **EDN-native**: Message formats in EDN, leveraging canonical-edn for deterministic serialization
4. **Simple API**: Learn from naclj's protocols and caesium's directness, but keep it simpler
5. **Composable**: Small, focused functions that compose well

## Platform Strategy

### JVM Backend
- **Ed25519**: `java.security.KeyPairGenerator` / `Signature` (Java 15+, JEP 339)
- **X25519**: `javax.crypto.KeyAgreement` with XDH (Java 11+, JEP 324)
- **SHA-256/512**: `java.security.MessageDigest`
- **Random**: `java.security.SecureRandom`
- **No external deps** — pure JCA

### ClojureScript Backend
- **Primary**: WebCrypto API (`crypto.subtle`) — Ed25519 + X25519 now in all browsers
- **Fallback**: @noble/curves for environments without WebCrypto Ed25519 support
- **SHA-256/512**: WebCrypto `crypto.subtle.digest`
- **Random**: `crypto.getRandomValues`

### Async Challenge
WebCrypto is Promise-based (async). Options:
1. **Async everywhere**: Return promises/channels on both platforms (consistent but verbose)
2. **Sync on JVM, async on JS**: Platform-specific calling conventions (natural but divergent)
3. **core.async**: Channels on both platforms (adds dependency)
4. **Promesa**: Cross-platform promise library (adds dependency)

**Recommendation**: Start with sync-on-JVM, promise-on-JS. Provide a unified macro/helper that abstracts the difference for common patterns. Consider `promesa` if a unified API is strongly desired.

## Proposed Namespace Structure

```
signet/
├── src/
│   └── signet/
│       ├── core.cljc          ;; Re-exports main API
│       ├── key.cljc           ;; Key generation, encoding, decoding
│       ├── sign.cljc          ;; Ed25519 signing and verification
│       ├── box.cljc           ;; X25519 key agreement + authenticated encryption
│       ├── hash.cljc          ;; SHA-256, SHA-512
│       ├── random.cljc        ;; Secure random bytes
│       ├── envelope.cljc      ;; EDN signed envelope format
│       ├── encoding.cljc      ;; hex, base64url, bytes conversions
│       └── impl/
│           ├── jvm.clj        ;; JCA implementations
│           └── js.cljs        ;; WebCrypto / noble implementations
```

## Key Representation

### Option A: Simple Maps (caesium-style)
```clojure
{:public <bytes>
 :secret <bytes>
 :algorithm :ed25519}
```
Pro: Simple, easy to destructure. Con: No behavior, just data.

### Option B: Records with Protocols (naclj-style)
```clojure
(defprotocol IKeyPair
  (public-key [kp])
  (private-key [kp])
  (algorithm [kp]))

(defrecord Ed25519KeyPair [public secret])
```
Pro: Extensible, type-safe. Con: More complex.

### Option C: Records with :type convention (best of both worlds)
```clojure
;; defrecord with :type field — is a map, has protocol dispatch
(defrecord Ed25519KeyPair [type public secret kid])

;; Construct with type tag
(->Ed25519KeyPair :signet/ed25519-keypair pub-bytes sec-bytes kid-str)

;; After cedn serialization, becomes a plain map with :type preserved
;; {:type :signet/ed25519-keypair :public #bytes "..." :secret #bytes "..." :kid "..."}

;; Reconstruct via multimethod dispatching on :type
(defmulti from-map (fn [m] (or (:type m) (type m))))
(defmethod from-map :signet/ed25519-keypair [m]
  (map->Ed25519KeyPair m))

;; Use derive to route the record's class to the same defmethod
(derive Ed25519KeyPair :signet/ed25519-keypair)
;; Now from-map works identically for plain maps AND existing records
```
Pro: Protocol dispatch, cedn-compatible, self-describing in EDN, idempotent round-trip.
The `:type` keyword is the single source of truth for identity — `derive` bridges
the class hierarchy to the keyword hierarchy so one defmethod handles both.

**Recommendation**: Option C — records with `:type` convention. Gets the benefits of
all three approaches: simple maps (EDN-native), protocol dispatch (extensible),
and self-describing type tags (serialization-friendly).

## Key Encoding Strategy

### Raw Keys (internal)
- Ed25519 public key: 32 bytes
- Ed25519 secret key: 64 bytes (seed + public)
- X25519 public key: 32 bytes
- X25519 secret key: 32 bytes

### Encoded Keys (interchange)
- **Primary**: base64url (URL-safe, compact)
- **Alternative**: hex (human-readable, debugging)
- **JVM interop**: X.509 (public) / PKCS#8 (private) for Java KeyPair compatibility
- **Key ID (kid)**: base64url of raw public key bytes (intrinsic, deterministic)

## Signed Envelope Format (EDN)

### Design Principles
- Self-describing (type tag)
- Includes signer identity (public key or kid)
- Canonical serialization via cedn before signing
- Timestamp via UUIDv7 (time-ordered, unique)
- No JSON compatibility required — pure EDN

### Proposed Format
```clojure
{:type :signet/signed
 :payload <any-edn-value>
 :signer {:kid "base64url-public-key"
          :alg :ed25519}
 :request-id #uuid "01966..."    ;; UUIDv7
 :signature #bytes "hex-of-signature"}
```

### Signing Process
1. Construct envelope: `{:payload value :signer {:kid kid :alg alg} :request-id (uuidv7)}`
2. Canonicalize: `(cedn/canonical-bytes envelope)`
3. SHA-256 hash: `(hash/sha256 canonical-bytes)` (optional — Ed25519 hashes internally)
4. Sign: `(sign/sign secret-key hash-or-canonical-bytes)`
5. Attach: `(assoc envelope :type :signet/signed :signature sig-bytes)`

### Verification Process
1. Extract envelope (remove :signature and :type)
2. Canonicalize
3. Hash (if used in signing)
4. Verify signature against signer's public key

## Encrypted Box Format (EDN)

### Proposed Format
```clojure
{:type :signet/encrypted
 :sender {:kid "base64url-sender-public-key"}
 :recipient {:kid "base64url-recipient-public-key"}
 :nonce #bytes "hex-of-24-byte-nonce"
 :ciphertext #bytes "hex-of-ciphertext"
 :alg :x25519-xsalsa20-poly1305}
```

### Anonymous Encryption (sealed box)
```clojure
{:type :signet/sealed
 :recipient {:kid "base64url-recipient-public-key"}
 :ephemeral-pk #bytes "hex-of-ephemeral-public-key"
 :ciphertext #bytes "hex-of-ciphertext"
 :alg :x25519-xsalsa20-poly1305}
```

## API Sketch

### Key Management
```clojure
(require '[signet.key :as key])

;; Generate keypairs
(key/generate-signing-keypair)       ;; → {:type :signet/ed25519-keypair ...}
(key/generate-encryption-keypair)    ;; → {:type :signet/x25519-keypair ...}

;; Encode/decode
(key/encode-public-key kp :base64url)
(key/decode-public-key bytes :ed25519)

;; Key identity
(key/kid kp)  ;; → "base64url-of-public-key"
```

### Signing
```clojure
(require '[signet.sign :as sign])

;; Low-level
(sign/sign secret-key message-bytes)   ;; → signature-bytes
(sign/verify public-key message-bytes signature-bytes) ;; → boolean

;; High-level (EDN envelope)
(sign/sign-edn keypair payload)        ;; → signed envelope map
(sign/verify-edn signed-envelope)      ;; → {:valid? true :payload ... :signer ...}

;; Close: sign-and-discard — proves possession of a key, then destroys
;; the ability to extend/delegate further (cf. Biscuit "seal")
(sign/close ephemeral-secret-key message-bytes) ;; → {:type :signet/closed :signature sig-bytes}
(sign/closed? proof)                             ;; → boolean
```

### Encryption
```clojure
(require '[signet.box :as box])

;; Authenticated encryption
(box/encrypt sender-kp recipient-pk plaintext-bytes) ;; → encrypted box map
(box/decrypt recipient-kp encrypted-box)              ;; → plaintext-bytes

;; High-level (EDN)
(box/encrypt-edn sender-kp recipient-pk edn-value)   ;; → encrypted box map
(box/decrypt-edn recipient-kp encrypted-box)           ;; → edn-value
```

## Implementation Phases

### Phase 1: Key Management + Signing (MVP)
1. Ed25519 keypair generation (JVM first, then JS)
2. Ed25519 sign/verify (raw bytes)
3. Key encoding (base64url, hex)
4. SHA-256 hashing
5. Signed EDN envelope (using canonical-edn)
6. Tests on JVM + ClojureScript

### Phase 2: Encryption
1. X25519 keypair generation
2. X25519 key agreement (Diffie-Hellman)
3. Symmetric encryption (XSalsa20-Poly1305 or XChaCha20-Poly1305)
4. Encrypted box format
5. Ed25519 → X25519 key conversion (use signing keys for encryption)

### Phase 3: Advanced Features
1. Key serialization/deserialization (EDN format)
2. SSH key import (OpenSSH Ed25519)
3. Key store abstraction
4. Sealed/anonymous boxes
5. Multi-recipient encryption

## Dependencies

### Required
- `org.clojure/clojure` (1.12+)
- `com.github.franks42/cedn` (canonical EDN)
- `com.github.franks42/uuidv7` (request IDs)

### Optional/Development
- `org.clojure/clojurescript` (for JS target)
- `@noble/curves` (JS polyfill, may become unnecessary as WebCrypto matures)

### Explicitly NOT needed
- libsodium / jnr-ffi
- Bouncy Castle
- buddy-core
- Any JSON library
