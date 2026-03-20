# Clojure Crypto Landscape Research

## Existing Clojure Libraries for 25519 Cryptography

### caesium (lvh/caesium) — Most Mature, JVM-only
- **Approach**: jnr-ffi binding to libsodium
- **Clojars**: `caesium/caesium "0.15.0"`
- **Coverage**: secretbox, box (Curve25519), sign (Ed25519), password hashing (argon2), generic hashing (BLAKE2b), random bytes, AEAD, key exchange, Ristretto255
- **Design**: Maps libsodium's C namespaces directly to Clojure namespaces
- **API style**: Operates on byte arrays, returns byte arrays. Keypairs as `{:public :secret}` maps
- **Limitation**: JVM only, requires native libsodium installed
- **Status**: Active (~691 commits), Eclipse Public License

### naclj (franks42/naclj) — Deprecated, JVM-only
- **Approach**: jnr-ffi to libsodium (similar to caesium)
- **Design**: Protocol-based with distinct record types per key type
- **Key innovation**: URN-based intrinsic key identifiers (`urn:nacl:pk:ed25519:<base64url>`)
- **JOSE exploration**: Design doc exploring JWK/JOSE representation of NaCl keys
- **Status**: Deprecated — README points to caesium

### fluree.crypto — Best Existing cljc Example
- **Clojars**: `fluree/crypto "4.0.0"`
- **Cross-platform**: JVM + Node.js + browser
- **Coverage**: Ed25519 signatures, JWS (RFC 7515/8037), DID (did:key), SHA-256/512, AES
- **Platform strategy**: JVM uses Java 17+ native Ed25519; JS uses @noble/ed25519
- **Supports**: GraalVM native compilation, multiple encodings (hex, base64, base58)

### buddy-sign — Most Popular Signing, JVM-only
- **Coverage**: JWS, JWT, JWE, and "compact" format (signs any Clojure type via nippy)
- **Ed25519**: Supported via `:eddsa` algorithm
- **Limitation**: JVM-only, no ClojureScript support

### Other Notable Libraries
| Library | Platform | Notes |
|---------|----------|-------|
| hiredman/ed25519 | JVM | Pure Clojure port of Python ed25519.py, proof-of-concept |
| geheimnis | cljc | AES/RSA/MD5 only — no 25519 |
| hasch | cljc | Deterministic SHA-512 hashing of EDN values (canonical serialization) |
| tweetnacl-java | JVM | Pure Java NaCl port, no native deps |
| salty-coffee | JVM | Pure Java NaCl, Java 11+, zero deps |
| TweetNaCl.js | JS | Via npm, usable from ClojureScript |

## Platform Crypto Capabilities

### Java (JVM)

**Ed25519 Signatures (JEP 339, Java 15+)**:
```java
KeyPairGenerator.getInstance("Ed25519")  // no init needed
Signature.getInstance("Ed25519")         // sign/verify
// Types: EdECPublicKey, EdECPrivateKey, EdECPoint
```

**X25519 Key Agreement (JEP 324, Java 11+)**:
```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
kpg.initialize(new NamedParameterSpec("X25519"));
KeyAgreement.getInstance("XDH")  // Diffie-Hellman
// Types: XECPublicKey, XECPrivateKey
```

### WebCrypto API (Browser/Node.js)

**Ed25519 (all major browsers as of 2025)**:
```javascript
await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data);
await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, data);
```

**X25519 (all major browsers as of early 2025)**:
```javascript
await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"]);
await crypto.subtle.deriveBits({ name: "X25519", public: theirKey }, myKey, 256);
```

**Key consideration**: WebCrypto is async-only (returns Promises).

### Polyfill Libraries
- **@noble/curves** (paulmillr): Pure JS, audited, Ed25519 + X25519 + more
- **@noble/ed25519**: Focused Ed25519 implementation
- Both useful as fallback when WebCrypto unavailable

## Key Gaps in the Ecosystem

No existing library combines all of:
1. **cljc portability** (JVM + ClojureScript)
2. **Ed25519 + X25519** (signing + key exchange/encryption)
3. **EDN-native message formats** (not JSON/JWS)
4. **Platform-native backends** (Java JCA + WebCrypto, minimal external deps)

This is exactly the gap signet aims to fill.
