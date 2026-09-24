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

## The vault: secrets by reference (0.8.0)

Application code holds **handles**, never secret bytes
(`docs/07-secret-handles-design.md`). A handle is a value:
`#signet.vault.KeyHandle{:type :signet/key-handle :kid "urn:signet:pk:…" :vault :default}`.
It names a key and the vault holding it, and it is safe to print, log,
serialise and send, because it contains nothing secret. It is a reference,
not a credential: the vault decides what it can do.

```clojure
(require '[signet.vault :as vault] '[signet.sign :as sign]
         '[signet.encryption :as enc] '[signet.shared :as shared])

(def me  (vault/generate-signing-key!))          ; born in the vault; the seed never leaves
(sign/sign-edn me {:op :read})                    ; signs inside the vault
(enc/box me bob-public-key (.getBytes "hi"))      ; key agreement inside the vault
(enc/unbox :default boxed)                        ; any key this vault holds; :to picks it
(def ab (shared/shared-key! me bob-public-key))   ; shared key, kept in the vault
(shared/seal ab plaintext)  (shared/open ab sealed)  (shared/mac ab msg)
```

- **Two sides, one kid:** `(vault/lookup kid)` answers from the public side
  (everyone's public keys), `(vault/handle kid)` only for keys the secret
  side holds. `vault/register-public-key!` adds a peer's key.
- **Keys are born in the vault** (`generate-signing-key!`,
  `generate-encryption-key!`). Secret bytes enter only through
  `import-signing-key!` / `import-encryption-key!`, which wipe the caller's
  array, and leave only through `(export-secret h {:i-understand :exposes-secret})`.
  `destroy!` wipes a key; its public key stays known.
- **Vaults route operations:** a handle's `:vault` names the vault
  (`register-vault!`); an unknown id throws `::unknown-vault`, never a
  fallback.
- **Providers:** on the libsodium backend the default provider is
  `:sodium`: keys live in libsodium's guarded memory (nacljc secrets: guard
  pages, locked against swap, no-access outside a call), and derived
  secrets (DH outputs, message keys, shared keys) stay there too. On the
  JCA backend it is `:memory`: secrets on the heap, inside the vault only,
  each lent copy wiped after use.
- **The default identity is the vault's:** `vault/ensure-default-signing-key!`,
  `set-default-signing-key!`. `sign/sign-edn!` and key-less `chain/extend`
  use it.
- **Chains:** an open token's `:proof` is a handle; `chain/export-token`
  (with the acknowledgement) gives the sendable form, `chain/import-token!`
  takes a received one into your vault, `close` and `chain/discard!`
  destroy the proof.
- **Shared keys** (`signet.shared`): both parties derive the same key and
  kid with no exchange. `seal` is directional and key-committing; a MAC is
  not a signature, and a static-static shared key has no forward secrecy.

Key records (`signet.key`, carrying `:d`) still work everywhere and remain
the raw layer. Sessions use them until they move onto vault handles, in the
release after 0.8.0.

## Keys: what is stored, what is not

- **Only functions whose names end in `!` write the key store or the
  defaults.** Creating and converting keys is pure: `signing-keypair`,
  `encryption-keypair`, `public-key`, `encryption-public-key`, `hex->kid`,
  `raw-shared-secret`, `ssh/load-keypair` and the rest never register
  anything. Where registering is a convenience there is a `!` twin that
  also registers and returns the key: `signing-keypair!`,
  `encryption-keypair!`, `ssh/load-keypair!`. Otherwise call
  `key/register!` yourself.
- **Registering never picks your default identity.** The default identity
  is the vault's (`vault/ensure-default-signing-key!`, see above).
  `sign/sign-edn` always takes an explicit key or handle.
- `key/lookup` and `key/kid` are pure too: resolving a kid from an
  envelope never adds it to the store, so untrusted input cannot grow
  memory.
- **Printing never shows a secret.** Key records print as
  `#signet/key {:type … :kid … :d "<redacted>"}` everywhere: the REPL, logs,
  `tap>`, ex-data. Serialising a key record as data (cedn, or walking it as
  a map) still exposes `:d`: use vault handles, which contain no secret.
- **Ephemeral keys are never exposed, never stored, and wiped after use.**
  Session and chain code creates them internally. Noise session
  ephemerals, and every DH output, are zeroed as soon as they have been
  used. Without that there is no forward secrecy. An open chain's
  ephemeral key lives in the vault, behind the token's `:proof` handle,
  until the chain is sealed.
- **Nonces are never the caller's job.** `box` draws its nonce internally,
  and a session counts its own nonces. Session states are single-use:
  `write-message!` / `read-message!` consume the state they are given and
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
| `sodium` | `signet.impl.sodium` | libsodium >= 1.0.19 (`brew install libsodium`), [nacljc](https://github.com/franks42/nacljc) 0.1.0 from Clojars (added by the `:sodium` alias), JDK 25+ with `--enable-native-access=ALL-UNNAMED`, or bb >= 1.13.220 | The full test suite also passes on babashka. |

```bash
clojure -M:test:sodium      # the :sodium alias adds nacljc and selects the backend
SIGNET_BACKEND=sodium bb …  # on babashka, with com.github.franks42/nacljc 0.1.0 added (see bb test:bb-sodium)
```

## Compatibility

**Upgrading from 0.6.0:** see [CHANGELOG.md](CHANGELOG.md). In short:

- Creating and converting keys no longer registers them. Use the `!`
  twins (`signing-keypair!`, `encryption-keypair!`, `ssh/load-keypair!`)
  or `register!` where you relied on it.
- Registering no longer sets the default. Call
  `set-default-signing-keypair!` or `ensure-default-signing-keypair!`.
- `(sign-edn payload)` is now `(sign-edn! payload)`.
- `session/write-message` and `session/read-message` are now
  `write-message!` and `read-message!`.
- Errors are ex-info with a namespaced `:type`. Session errors are the
  same on every backend.

**Trust fixes (0.7.0, PR #1):** an expired envelope is no
longer `:valid?`. The raw signature check is now `:signature-valid?`, and
`:error` says why an envelope is invalid. `key/lookup` no longer registers
the keys it parses from kids, and `key/kid` no longer registers anything.
Code that relied on either for registration must call `key/register!`
explicitly.

### cedn 1.6.0

signet signs canonical EDN bytes produced by cedn. signet 0.7.1 depends
on cedn 1.6.0. That release only renames functions (`check`, `throw-*`),
so the canonical bytes, and therefore signatures, are identical to 1.5.2,
which 0.7.0 used. Before 0.7.0, signet used cedn 1.2.0, and cedn 1.4.0
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
bb test:no-sodium    # lint + fmt + JCA suite + bb smoke (no native libsodium needed)
bb test:all          # test:no-sodium + test:jvm-sodium + test:bb-sodium
bb test:jar          # install signet's jar, run its tests from a scratch consumer: jca, sodium + parity, bb
```

CI runs the same bb tasks: JCA on Ubuntu (JDK 21 and 25), and the libsodium
backend on macOS and Linux. On Linux, babashka.ffi needs the **dynamically
linked** bb build; the static one cannot load libsodium. Ubuntu's packaged
libsodium (1.0.18) is too old, so CI builds 1.0.22 from source.
