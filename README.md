# Signet

Ed25519 / X25519 signing and encryption for Clojure with EDN-native
envelopes. Canonical EDN ([cedn](https://github.com/franks42/canonical-edn))
is the signed bytes and [uuidv7](https://github.com/franks42/uuidv7.cljc)
provides request ids. Also provides capability chains (`signet.chain`),
sender-authenticated encryption (`signet.encryption`), Noise_KK sessions
(`signet.session`) and SSH key import (`signet.ssh`).

Runs on the JVM and babashka. ClojureScript is not implemented yet.

## Valid, verified, authorized

signet keeps three questions apart:

- **Valid:** the envelope is well-formed, the signature checks out under
  the key named in `:signer`, and it hasn't expired. This is only
  self-consistency: anyone can produce a valid envelope with their own key.
- **Verified:** valid, *and* the signer (or a chain's root) is the identity
  you expected. Pass it in, as one kid or a set of kids:
  `(sign/verify-edn env {:signer kid})`, `(chain/verify token {:root kid})`.
  The result then has `:verified?`, and `:valid?` also requires it.
- **Authorized:** whether that identity may do this. That's policy, and not
  signet's job. It belongs to a policy decision point such as stroopwafel's.

`verify-edn` and `chain/verify` never throw on malformed input; they return
`:valid? false` with an `:error`. Both take `:now` (epoch-ms) to judge
expiry deterministically; without it they read the clock.

## Boxes (authenticated encryption)

`signet.encryption/box` returns a self-describing EDN map (box v2, see
`docs/06-box-v2-design.md`):

```clojure
(box alice bob (.getBytes "hi"))           ; => {:type :signet/box :v 2 :from … :to … :nonce … :ct …}
(box alice bob pt {:aad {:req 42} :from? false :to? false})
(unbox bob boxed)                          ; => {:valid? true :plaintext … :from … :aad …}
(unbox [bob carol] boxed {:from alice-kid :aad {:req 42}})  ; also :verified?
```

- **Directional keys:** a box cannot be reflected back to its sender.
- **Unique key per message:** a random 24-byte salt, so random nonces are
  safe at any volume. The caller never handles a nonce.
- The optional `:from` and `:to` kid slots (on by default) and `:aad` are
  authenticated. Omitted kids are still bound.
- `unbox` never throws on malformed input.

## Keys: what is stored, what is not

- The key store holds only keys you create or register deliberately.
  `key/lookup` and `key/kid` are pure: resolving a kid from an envelope
  never adds it to the store, so untrusted input cannot grow memory.
- **Ephemeral keys are never exposed, never stored, and wiped after use.**
  Session and chain code creates them internally. Noise session
  ephemerals, and every DH output, are zeroed as soon as they have been
  used. Without that there is no forward secrecy. An open chain's
  ephemeral key lives in the token's `:proof` until the chain is sealed.
- **Nonces are never the caller's job.** `box` draws its nonce internally,
  and a session counts its own nonces. Session states are single-use:
  `write-message` / `read-message` consume the state they are given and
  return the one to use next. Using a consumed state again throws
  `::stale-session-state`, so a nonce can never be reused and a replayed
  message cannot be accepted twice from a stale state. A failed read
  (tampered or forged message) does not consume the state.
  `signet.impl*` namespaces expose raw AEAD with explicit nonces for
  signet's own use only. They are internal, not public API.

## Crypto backends

`signet.impl` selects the backend once, when it loads: the JVM system
property `signet.backend`, then the environment variable `SIGNET_BACKEND`,
then the default `jca`. Both backends produce byte-identical signatures,
keys and ciphertexts.

| Backend | Namespace | Needs | Notes |
|---|---|---|---|
| `jca` (default) | `signet.impl.jvm` | a JDK | No native dependency. Deriving a public key from a seed does not work on babashka. |
| `sodium` | `signet.impl.sodium` | libsodium >= 1.0.19 (`brew install libsodium`), [sodium.cljc](https://github.com/franks42/sodium.cljc) as a local snapshot jar (`bb install` in sodium.cljc; not published yet), JDK 25+ with `--enable-native-access=ALL-UNNAMED`, or bb >= 1.13.220 | The full test suite also passes on babashka. |

```bash
clojure -M:test:sodium      # the :sodium alias adds sodium.cljc and selects the backend
SIGNET_BACKEND=sodium bb …  # on babashka, with com.github.franks42/sodium 0.1.0-SNAPSHOT added (see bb test:bb-sodium)
```

## Compatibility

**Trust fixes (0.7.0-SNAPSHOT, PR #1):** an expired envelope is no
longer `:valid?`. The raw signature check is now `:signature-valid?`, and
`:error` says why an envelope is invalid. `key/lookup` no longer registers
the keys it parses from kids, and `key/kid` no longer registers anything.
Code that relied on either for registration must call `key/register!`
explicitly.

### cedn 1.5.2

signet signs canonical EDN bytes produced by cedn. Since 0.7.0-SNAPSHOT
(PR #1) it depends on cedn 1.5.2 (before: 1.2.0). cedn 1.4.0
changed the canonical bytes for some inputs to fix determinism and
injectivity bugs. Those inputs are sets or maps containing `#inst` values,
integers above 2^53, and integers next to doubles near 2^53. A signature
made with cedn 1.2.0 over such a payload no longer verifies. cedn 1.4.0+
also rejects payloads 1.2.0 accepted ambiguously, such as `(symbol "nil")`,
which serialized like `nil`. Other payloads are unaffected. See cedn's
CHANGELOG for 1.4.0 and 1.5.0.

## Development

```bash
bb test:jvm   bb test:jvm-sodium   bb test:bb-sodium   bb smoke
bb lint       bb fmt
```
