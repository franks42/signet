# The JCA Seed-to-Public-Key Trick

## The Problem

In Ed25519 (and X25519), the public key is deterministically derived from the private key seed. This is a fundamental property of elliptic curve cryptography — given the 32-byte seed, there is exactly one corresponding public key.

You'd think Java's JCA would expose this as a simple function call:

```java
byte[] publicKey = Ed25519.derivePublicKey(seed);  // doesn't exist
```

But it doesn't. The JCA provides:
- `KeyPairGenerator.generateKeyPair()` — generates a **random** keypair
- `KeyFactory.generatePrivate(PKCS8EncodedKeySpec)` — reconstructs a private key from encoded bytes
- `KeyFactory.generatePublic(X509EncodedKeySpec)` — reconstructs a public key from encoded bytes

Notice the gap: you can go from encoded public key bytes → public key object, and from encoded private key bytes → private key object. But there's no `privateKey → publicKey` derivation in the public API.

The actual derivation logic exists internally as a `private` method (`calculatePublicKey`) inside `sun.security.ec.ed.EdDSAPrivateKeyImpl`. Java's module system (`jdk.crypto.ec`) blocks reflection access to it.

## The Trick

`KeyPairGenerator.initialize()` accepts a `SecureRandom` parameter — the source of randomness used during key generation. Normally this is, well, random. But nothing in the API contract requires it to be.

The key insight: Ed25519 key generation is just:
1. Get 32 bytes from `SecureRandom` → that's the seed
2. Derive the public key from the seed (the private method we can't call)
3. Return both as a `KeyPair`

So if we provide a `SecureRandom` that returns **our known seed** instead of random bytes, the `KeyPairGenerator` will derive the corresponding public key for us:

```clojure
(defn- seed->keypair-via-kpg
  [^String algorithm ^bytes seed-bytes]
  (let [seed-copy (byte-array seed-bytes)
        fake-random (proxy [SecureRandom] []
                      (nextBytes [^bytes bytes]
                        (System/arraycopy seed-copy 0 bytes 0
                                          (min (count bytes) (count seed-copy)))))
        kpg (KeyPairGenerator/getInstance algorithm)]
    (.initialize kpg (NamedParameterSpec. algorithm) fake-random)
    (.generateKeyPair kpg)))
```

That's it. We feed the seed in, and extract the public key from the resulting `KeyPair`. The JCA does all the elliptic curve math internally, through the exact same code path it uses for normal key generation.

## Why This Works

```
Normal key generation:
  KeyPairGenerator asks SecureRandom for 32 bytes
    → gets RANDOM bytes
    → derives keypair (seed → public key via scalar multiplication)
    → returns KeyPair

Our trick:
  KeyPairGenerator asks SecureRandom for 32 bytes
    → gets OUR SEED
    → derives keypair (seed → public key via scalar multiplication)
    → returns KeyPair

Same code path. Same math. Same result.
We just controlled the input.
```

## Why Not Alternatives?

| Approach | Problem |
|----------|---------|
| Reflection on `calculatePublicKey` | Java module system blocks access to `jdk.crypto.ec` internals |
| Bouncy Castle | Heavy dependency just for one scalar multiplication |
| Pure Java Ed25519 implementation | Hundreds of lines of subtle curve arithmetic to get right |
| `KeyFactory.getKeySpec()` | `EdECPrivateKeySpec` only returns the seed, not the public key |
| `KeyFactory.translateKey()` | Returns the same private key, no public key derivation |

## Properties

- **No reflection** — uses only public JCA APIs
- **No external dependencies** — pure JDK
- **Module-system safe** — no `--add-opens` flags needed
- **Same code path** — uses the exact same derivation logic as normal key generation
- **Works for both Ed25519 and X25519** — same trick, different algorithm name
- **Robust across JDK versions** — the API contract is stable; the internal implementation can change freely

## The One Assumption

This assumes that `KeyPairGenerator` for Ed25519 consumes exactly 32 bytes from `SecureRandom` as the seed. This is inherent to the Ed25519 specification (RFC 8032) — the seed is defined as 32 bytes. If that ever changed, it wouldn't be Ed25519 anymore.

## Usage in Signet

```clojure
(require '[signet.key :as key])

;; "I only have the private seed, give me the full keypair"
(key/signing-keypair {:type :signet/ed25519-private-key
                      :crv  :Ed25519
                      :d    seed-bytes})
;; => Ed25519KeyPair with :x (public key) derived automatically

;; Same for X25519
(key/encryption-keypair {:type :signet/x25519-private-key
                         :crv  :X25519
                         :d    private-key-bytes})
;; => X25519KeyPair with :x (public key) derived automatically
```

---

*Discovered while building [Signet](https://github.com/franks42/signet), a portable Clojure(Script) library for Ed25519/X25519 cryptography. The trick emerged from an AI-assisted exploration of JCA internals when we hit the `calculatePublicKey` wall.*
