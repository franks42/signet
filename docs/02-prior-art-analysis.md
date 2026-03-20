# Prior Art Analysis: naclj, caesium, stroopwafel

## naclj — Interface Design Lessons

### Strengths (to adopt)
- **Protocol-based design**: `IKey`, `IKeyPair`, `IPrivateKey`, `IPublicKey`, `ISigningKeyPair`, `IEncryptionKeyPair` — clean separation of concerns
- **Intrinsic key identifiers**: URN-based (`urn:nacl:pk:ed25519:<base64url>`) — deterministic, no external registry needed
- **Rich encoding protocols**: `IBytesEncode`, `IHexEncode`, `Ibase64urlEncode` — keys naturally convert between representations
- **Factory pattern**: `(make-key-pair :sodium :ed25519)` — extensible via multimethods
- **JOSE exploration**: Thoughtful mapping of NaCl keys to JWK format

### Weaknesses (to avoid)
- **JVM-only**: No ClojureScript path
- **Heavy protocol hierarchy**: Too many protocols/records for a simple use case
- **libsodium dependency**: Requires native library installation
- **Incomplete msg-box**: Higher-level message boxing was never finished

### Key Types & Records
- `TEd25519KeyPair`, `TEd25519PrivateKey`, `TEd25519PublicKey`
- `TCurve25519KeyPair`, `TCurve25519PrivateKey`, `TCurve25519PublicKey`, `TCurve25519DHKey`
- Key conversion: Ed25519 ↔ Curve25519 (for using signing keys for encryption)

## caesium — API Design Lessons

### Strengths (to learn from)
- **Direct libsodium mapping**: Predictable namespace structure mirrors C API
- **Minimal wrapping**: No magic, no hidden security implications
- **Both high-level and low-level**: `box-easy` vs `box-detached` vs raw `to-buf!`
- **Comprehensive**: Covers entire libsodium surface area
- **Well-tested**: Extensive test suite with test vectors

### API Pattern
```clojure
;; Keypairs as simple maps
(caesium.crypto.sign/keypair!)       ;; → {:public bytes :secret bytes}
(caesium.crypto.box/keypair!)        ;; → {:public bytes :secret bytes}

;; Signing
(caesium.crypto.sign/sign msg sk)    ;; → signature-bytes
(caesium.crypto.sign/verify sig pk)  ;; → throws on failure

;; Encryption
(caesium.crypto.box/encrypt pt nonce their-pk my-sk) ;; → ciphertext
(caesium.crypto.box/decrypt ct nonce their-pk my-sk) ;; → plaintext
```

### Weaknesses (to avoid)
- **JVM-only**: libsodium native dependency
- **Low-level byte arrays**: No higher-level message format
- **No key serialization**: Keys are bare byte arrays, no metadata

## stroopwafel — Requirements Source & Consumer

### What stroopwafel needs from signet
1. **Ed25519 keypair generation** — currently uses `KeyPairGenerator.getInstance("Ed25519")`
2. **Ed25519 sign/verify** — via `Signature.getInstance("Ed25519")`
3. **SHA-256 hashing** — via `MessageDigest.getInstance("SHA-256")`
4. **Key encoding** — X.509 (public, 44 bytes), PKCS#8 (private, 48 bytes)
5. **SSH key import** — OpenSSH Ed25519 format → Java key objects
6. **Deterministic serialization** — uses canonical-edn (cedn) before signing

### stroopwafel's Signing Pattern
```clojure
;; 1. Construct envelope (map with :message, :signer-key, :request-id, :expires)
;; 2. Canonicalize via cedn/canonical-bytes
;; 3. SHA-256 hash the canonical bytes
;; 4. Ed25519 sign the hash
;; 5. Return {:type :stroopwafel/signed-envelope :envelope env :signature sig}
```

### stroopwafel's Key Format
- Public keys: X.509 encoded bytes (44 bytes for Ed25519)
- Private keys: PKCS#8 encoded bytes (48 bytes for Ed25519)
- Key identity: by public key bytes (used in `:signer-key`, `:next-key`, `:external-key`)

### Implications for signet
- Must support the same signing workflow (canonicalize → hash → sign)
- Key encoding should be compatible with Java's X.509/PKCS#8 or provide conversion
- Should integrate naturally with canonical-edn and uuidv7
- Ephemeral keypair generation must be fast (stroopwafel creates one per block)
- Cross-platform: stroopwafel currently runs on JVM + Babashka, wants ClojureScript too

## canonical-edn — Essential Dependency

### Role in the Ecosystem
- Provides **deterministic EDN serialization** — same data → same bytes, always
- Required for signing EDN data structures (maps/sets have non-deterministic iteration)
- Cross-platform: JVM, Babashka, ClojureScript, nbb, browser

### Key API
```clojure
(cedn/canonical-bytes value)  ;; → byte array (deterministic UTF-8)
(cedn/canonical-str value)    ;; → string
(cedn/valid? value)           ;; → boolean (type check)
```

### Supported Types
nil, boolean, int, double, string, keyword, symbol, list, vector, set, map, #inst, #uuid, #bytes

## uuidv7 — Complementary Dependency

### Role in the Ecosystem
- Provides **monotonic, time-ordered unique identifiers**
- Used for request IDs, replay protection, temporal ordering
- Cross-platform: JVM, ClojureScript, Babashka, nbb

### Key API
```clojure
(uuidv7/uuidv7)        ;; → UUID (monotonic within millisecond)
(uuidv7/extract-ts u)   ;; → epoch-ms
(uuidv7/uuidv7? u)      ;; → boolean
```
