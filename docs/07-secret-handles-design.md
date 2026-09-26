# Secrets by reference: handles and a vault

Status: **released in 0.8.0** (2026-09-24). Implemented:
handles and the vault registry, the two sides, keys born in the vault,
import/export/destroy, the `:memory` and `:sodium` providers, sign / box /
chain on handles, and shared keys (`signet.shared`). Sessions on handles
followed in 0.9.0 (decision 9, docs/08). "Decisions so far" at the end
lists what is settled; the open questions remain open. "Future: enclave
tiers" (2026-09-25) describes how hardware and remote providers fit in.

## The principle

**Application code should never see private or secret keys.** It refers to
a secret by a handle, and the secret lives in a vault. An operation
resolves the handle inside the vault, uses the secret, and wipes any
working copy. The secret is never returned. Moving secret bytes across the
vault boundary takes an explicit, deliberately named import or export.

This is how serious key management already works:

| System | How it works |
|---|---|
| PKCS#11 and HSMs | Callers get object handles; private keys are marked non-extractable. |
| ssh-agent | Clients ask the agent to sign and never see the key. |
| WebCrypto | `CryptoKey` with `extractable: false`, now also for Ed25519 and X25519. |
| Android Keystore, Apple Secure Enclave, cloud KMS | Operations run inside the key's home, and callers only get results. |
| Rust `secrecy` | A `Secret<T>` whose debug output is redacted; access goes only through `expose_secret()`. |

## Why: where secrets are exposed today

Findings from 2026-09-23 [verified]:

- **Serialisation dumps them.** `cedn/canonical-str` of a keypair writes
  `:d`, the private key, in full hex. So does anything that walks a record
  as a map (`into {}`, `select-keys`, `clojure.walk`).
- **Printing is safe only by accident.** On the JVM and bb, `pr-str`
  shows `:d` as an opaque `#object["[B" …]`. On nbb, which signet's
  upcoming ClojureScript side will use, the same call prints the bytes:
  `#object[Uint8Array 222,173,190,239]`.
- **Keys are plain data.** Keypairs are records holding raw byte arrays.
  They are copied, compared (by identity, since arrays compare that way),
  passed to logging, and kept in a global atom (the key store) that
  persistent-map semantics never clear: an old version of the map still
  holds the bytes until the garbage collector runs.
- **JVM arrays cannot be reliably wiped.** The garbage collector may have
  copied an array before `Arrays/fill` zeroes the one we hold (see
  nacljc's README, "Memory and type safety").
- **Session states hold secrets in maps.** The transport keys and chaining
  key (`k`, `ck`) are plain arrays inside state maps.
- **The naming convention makes this more urgent.** Under the
  pure/`!`-twin rule (see "Decisions so far"), pure constructors would
  *return* keys instead of hiding them in the store. That puts more
  secrets into return values, and so into code that prints and serialises.

## Goals

1. Public API functions take and return **handles and public keys only**.
2. Secret bytes cross the vault boundary only through **explicit, named,
   grep-able** import and export functions.
3. **Keys are born in the vault.** Generation returns a handle; the secret
   never exists outside the vault.
4. **Pluggable providers:** the same handle API over an in-process vault,
   native protected memory, and later WebCrypto, an agent or a keychain.
5. **Nothing secret in printing, serialisation or error data,** enforced by
   types rather than by discipline.
6. The **pure core stays pure** (`signet.impl.*`, nacljc work on bytes
   internally). The handle layer is the imperative shell, and names its
   writes with `!`.

## Threat model

What this protects against: **copies and accidental exposure.** That
covers logs, printing, `tap>`, the REPL, serialisation mistakes, ex-data,
crash reports and heap dumps. With native protected memory it also covers
swap and stray reads of idle key memory.

What it does not protect against: **code running inside the process**. Such
code can call the vault and *use* any key it can reach. Only an
out-of-process provider (agent, HSM, KMS, Secure Enclave) prevents
*copying* the key, and even then it can still be *used*. Nor does it defend
against a memory-reading attacker at the moment a key is in use.

This section belongs in the README once the model ships, so users do not
over-read the guarantee.

## The model

### Handles

```clojure
{:type :signet/key-handle
 :kid  "urn:signet:pk:ed25519:…"   ; the public key; identifies the key
 :vault :default}                   ; which vault holds the secret
```

A handle contains nothing secret. It is safe to print, log, serialise,
compare and send. For Ed25519 and X25519 the kid *is* the public key, so a
handle also gives the public key without touching the vault.

### Vault

The vault holds the secret material, indexed by kid. It evolves from
today's key store:

- **Public side:** kids and public keys for `lookup`. It never holds a
  secret.
- **Secret side:** **mutable**, not a persistent map, so that removing an
  entry really removes it. Removing frees the secret and wipes it.

A default vault exists for convenience. Every function also accepts an
explicit vault, as the key store functions accept an explicit store today.

### Provider protocol

Operations the vault must support, over a handle:

| Operation | Returns |
|---|---|
| `sign` handle msg | signature |
| `dh` handle their-public-key | shared secret, **kept in the vault** as a new handle (see "Derived secrets" and "Shared symmetric keys") |
| `open-box` handle boxed | plaintext |
| `public-key` handle | public key |
| `generate!` algorithm | handle |
| `import!` secret-bytes | handle |
| `export` handle | secret bytes (deliberately named, documented as dangerous) |
| `destroy!` handle | nil; wipes and removes the secret |

Providers, in the order they would come:

| Provider | Where the plaintext lives | Notes |
|---|---|---|
| `:memory` | JVM heap, inside the vault only | Level 1 below. Default on the JCA backend. |
| `:memory-encrypted` | heap, encrypted under a per-process vault key; decrypted into a scratch buffer just before use, wiped straight after | Level 2. A fallback where native memory is not available. |
| `:sodium` | libsodium secure memory: `sodium_malloc` (guard pages, `mlock`), `sodium_mprotect_noaccess` between uses, `sodium_free` zeroes it | Level 3. **Never on the JVM heap.** Needs nacljc 0.2.0. |
| `:webcrypto` | browser, non-extractable `CryptoKey` | For signet's ClojureScript side. |
| `:agent`, `:keychain`, `:hsm` | out of process | Level 4. Later. |
| `:pkcs11` | any PKCS#11 token (SoftHSM for tests; YubiHSM, CloudHSM, smartcards) | Level 4. One provider for every existing HSM; see "Future: enclave tiers". |
| `:tpm`, `:piv`, `:secure-enclave`, `:fido2` | hardware on this machine | Level 4. Slow and narrow: unlock and endorse only (see "Future: enclave tiers"). |

### Protection levels

| Level | Protects against | Cost |
|---|---|---|
| 1. Handle and in-process vault | accidental exposure through printing, logs, serialisation and ex-data; only vault code touches bytes | small: an API change |
| 2. Encrypted at rest in memory | also heap dumps and swap catching an idle copy. **But** the vault key lives in the same process, so this mostly shortens the plaintext's exposure window | small, plus one AEAD call per use |
| 3. Native protected memory | also GC copies (the plaintext never touches the Java heap), swap (`mlock`), and stray reads of idle keys, which crash instead of reading them | nacljc work; one `mprotect` system call per use |
| 4. Out of process | copying the key at all | a provider per system |

Level 3 is preferred over level 2 wherever it is available. Encrypting
memory with a key held in the same memory is weaker than memory that the
operating system protects.

## What changes, area by area

### Keys (`signet.key`)

- `generate-signing-key!` and `generate-encryption-key!` create the key
  **inside the vault** and return a handle.
- `import-signing-key!` and `import-encryption-key!` take secret bytes
  (key files, backups, SSH import) and return a handle. The docstring says
  "handle with care". These are the only way secret bytes enter.
- `export-secret` returns secret bytes. It is the only way they leave, it
  is grep-able, and its docstring warns.
- `destroy!` handle.
- Public-key conversions (`public-key`, `encryption-public-key`,
  `kid`, `lookup`) stay pure and take handles or public keys.
- Keypair records with raw `:d` stop being public API. They remain an
  internal representation inside the `:memory` provider.

### Signing (`signet.sign`, `signet.chain`)

- `(sign-edn handle payload [opts])`: the handle replaces the keypair.
  It is still impure (it reads the clock and draws a request ID), needs no
  `!`, and has an `Impure:` docstring line.
- `(sign-edn! payload)`: the convenience that uses the default identity, or
  generates one and sets it as default (decided, option b).
- `chain/extend` takes handles for the root. An open token's `:proof` is an
  ephemeral private key *by design*, since a bearer token carries it.
  Locally it is a handle. Sending the token exports it, and the export is
  explicit and documented as a bearer credential. A token prints with
  `:proof` redacted.

### Box (`signet.encryption`)

- `(box handle recipient-public-key plaintext [opts])`.
- `(unbox vault boxed [opts])`: the vault chooses the recipient key from the
  box's `:to` kid. This is simpler than today's list of candidate keypairs.
  A handle or a set of handles still limits the choice explicitly.

### Sessions (`signet.session`)

- A state holds **handles** to the chaining key and the transport keys in
  the vault, instead of arrays.
- Consuming a state (`write-message!`, `read-message!`) destroys the
  entries it no longer needs.
- This is the largest refactor, and the most valuable one: nonces and
  wiping matter most here. Done in 0.9.0 (docs/08), with `close!` and
  `with-conclave` to end a session.

### Derived secrets

`dh` / `edh` outputs, HKDF outputs and session keys are secrets too. The
rule: **a secret derived from a vault secret stays in the vault** and is
returned as a handle. The pure core (`impl`, `mix-key!`) still works on
bytes, inside the provider.

### Shared symmetric keys (from a DH exchange)

Proposed 2026-09-23. Two parties that talk often want to agree once, keep
the result, and then encrypt, decrypt and authenticate messages cheaply,
without a full box or session each time. The derived key stays in the
vault under a handle, like every other secret:

```clojure
(def h (vault/shared-key! my-handle their-pub {:context "app/v1"}))
(vault/seal h plaintext)          ; → EDN box: per-message salt, directional key
(vault/open h boxed)              ; → {:valid? … :plaintext …}; never throws
(vault/mac h msg)                 ; → tag
(vault/verify-mac? h msg tag)     ; → boolean; never throws
(vault/destroy! h)
```

Rules:

1. **Never use the raw DH output as a key.** `shared-key!` runs it through
   HKDF with a context (both kids, a purpose label, and the caller's
   `:context`) and derives **separate keys per purpose**: one for
   encryption, one for MAC. It also derives **separate keys per
   direction**, as box v2 does, so a message cannot be reflected back to
   its sender as if the peer had sent it. The raw output is wiped
   immediately.
2. **No caller-chosen nonces, ever.** A long-lived symmetric key with
   caller-chosen nonces is exactly how nonce reuse happens. Two safe modes:
   - **Stateless (the default):** every `seal` derives a one-message key
     from a fresh random salt, as box v2 does. It is safe at any volume,
     needs no shared state, and survives restarts.
   - **Stateful:** counters with single-use states, which is what
     `signet.session` already does. Sessions remain the tool for that.
3. **A MAC is not a signature.** Both parties hold the key, so either could
   have produced a tag. `mac` authenticates between the two parties, but
   proves nothing to a third party about which of them wrote a message. The
   API says `mac` / `verify-mac?`, never `sign`, and its docstring says so.
   For non-repudiation, use `sign-edn`.
4. **No forward secrecy.** A key derived from static-static DH lives as
   long as both long-term keys. If either leaks, everything protected by
   that shared key is exposed. The docstring states this. Conversations that
   need forward secrecy use `signet.session`.
5. **A key-derived id that only holders can compute** (settled
   2026-09-23, decision 16). A symmetric key has no public part, so its id
   is derived from the shared secret by the same HKDF that produces the
   encryption and MAC keys:
   `kid = HKDF-Expand(PRK, "signet/shared/v1/kid", 32)`, written
   `urn:signet:shared:<base64url>` ("shared" rather than "sk", which reads
   like "secret key"). Every holder computes the same id, no one else can,
   and it reveals nothing about the other derived keys (independent HKDF
   outputs). It names the relationship as a whole; the encryption keys
   underneath stay directional. Not a plain hash of the key (see decision
   16), and not a hash of both parties' kids, which anyone could compute
   and which would show who talks to whom. Locally the vault also keeps a
   private index from (my kid, peer kid, context) to the handle; that
   index never leaves the vault.
6. **It lives in the vault only.** It never goes into today's key store,
   which is a plain map where the key would be visible. `export-secret` is
   the only way out, as for any secret.

Relation to what exists: `key/raw-shared-secret` returns the bare DH
output today. That is fine as a primitive, but it is not a key to use
directly. `shared-key!` is the safe, vault-resident way to get one.

Open: the AEAD for `seal`. The default is ChaCha20-Poly1305 with a
per-message HKDF key, as in box v2. AEGIS-256 could replace that
construction, and key commitment belongs here too (Open questions 9–11).
`seal`'s output names its suite exactly as a box does.

### Defaults

`register!` no longer sets defaults (decided). The default identity is
chosen explicitly: `set-default-signing-key!` with a handle, or
`sign-edn!`'s first use.

## nacljc: native secrets (0.2.0)

nacljc would add a native secret type, created and held in
`sodium_malloc` memory:

- `(secret-generate n)`, `(secret-import bytes)`: return an opaque secret
  object. Importing copies the bytes in and wipes the caller's array.
- Operations accept the secret object wherever they accept a secret key
  today: `ed25519-sign`, `x25519`, `hkdf-sha-256`, the AEAD. The bytes are
  never copied to the Java heap. Access is `mprotect`ed read-only for the
  duration of the call, and no-access otherwise.
- `(secret-destroy! s)`: `sodium_free`, which zeroes the memory; later use
  throws.
- The same C-boundary rules as 0.1.0 apply, and the same kind of test
  audit: every mprotect transition, and no-access outside calls.

signet's `:sodium` provider is built on this. The JCA backend gets the
`:memory` or `:memory-encrypted` provider.

## Naming and purity, applied

- Writes to a vault are `!`: `generate-signing-key!`, `import-…!`,
  `destroy!`, `sign-edn!`.
- `export-secret` has no `!`, because it reads, but its name says what it
  reveals.
- Every function states `Impure: …` and `Throws ex-info {:type …} when …`
  in its docstring, per the naming convention (CLAUDE.md, "Naming: purity,
  `!` and exceptions").
- **The twin rule, refined for secrets.** A pure function that would have
  to *return* a secret in order to let the caller register it would
  contradict the principle. For secrets, the element is born in the vault,
  and the only pure-side access is explicit export. The twin rule still
  applies to everything non-secret.

## Test plan

- **No secret on any output path:** for every handle and key type,
  `pr-str`, `str`, `cedn/canonical-str`, ex-data and printed exceptions
  contain no secret bytes (hex or decimal), and serialising a vault secret
  throws.
- **The vault boundary:** the public API (pinned by a test) has no
  function returning secret bytes except `export-secret`.
- **Lifecycle:** after `destroy!`, the handle fails with a typed error, and
  on `:sodium` the memory has been freed through `sodium_free`.
- **Derived secrets stay in:** `dh`, HKDF and session keys come back as
  handles.
- **Purity:** pure functions leave the vault and the defaults unchanged
  (a table test).
- **Providers agree:** the same operations give byte-identical results on
  `:memory`, `:memory-encrypted` and `:sodium`, like the backend
  comparison today.
- **Each guard bites,** proven by removing it.

## Migration and release plan

1. **signet 0.8.0** (0.7.0 shipped the naming changes without vaults):
   handles plus the `:memory` provider behind the provider protocol. Also:
   - keys born in the vault, explicit import and export;
   - sign, box and chain on handles;
   - redacted printing as a safety net;
   - the public renames batched from the naming convention: pure key
     functions with `!` twins, `write-message!` and `read-message!`,
     `Impure:` and `Throws:` docstrings;
   - one-argument `sign-edn` replaced by `sign-edn!`.
2. **nacljc 0.2.0:** native secrets. Then signet's `:sodium` provider on
   them.
3. **Sessions on vault handles:** done in 0.9.0 (docs/08).
4. **Later:** `:memory-encrypted` where native is unavailable, `:webcrypto`
   for signet's ClojureScript side, then agent, keychain and HSM providers.

## Post-quantum suites

Proposed 2026-09-23. A quantum computer running Shor's algorithm breaks
X25519, Ed25519 and secp256k1. It does not meaningfully break the
symmetric layer: Grover's algorithm at best halves a symmetric key's
effective strength, so the 256-bit-key AEADs (ChaCha20-Poly1305,
AEGIS-256) keep about 128-bit security, and HKDF-SHA-256 and HMAC stay.
(AEGIS-128L's 128-bit key would drop to about 64 bits: one more reason to
prefer AEGIS-256.) **So a post-quantum suite keeps its AEAD component and
replaces the signing and key-exchange components.** But it still changes
the protocol, for the reasons below.

### Available now [verified 2026-09-23]

| Library | Key exchange | Signatures |
|---|---|---|
| libsodium 1.0.22 | ML-KEM-768; **X-Wing** (ML-KEM-768 + X25519 hybrid, "the recommended KEM for most" uses per its ChangeLog) | none |
| JDK 25 | ML-KEM (SunJCE) | ML-DSA (SUN) |
| Bouncy Castle 1.86 | ML-KEM | ML-DSA |

X-Wing sizes (libsodium headers): public key 1,216 bytes, ciphertext
1,120 bytes, secret key 32 bytes (a seed), shared secret 32 bytes.
ML-KEM-768: public key 1,184, ciphertext 1,088. ML-DSA-65: public key
1,952, signature 3,309.

### What changes, and why it is more than swapping primitives

1. **A KEM is not Diffie-Hellman.** ML-KEM (and X-Wing) *encapsulate* a
   secret to the recipient's public key. There is no value that both
   sides compute non-interactively from their static keys, as
   DH(sender, recipient) is today. Three designs rely on that:
   - **box v2** authenticates the sender through that DH. A PQ box carries
     a KEM ciphertext in its header *and* authenticates the sender
     separately: a signature by the sender's (hybrid) signing key over the
     header and ciphertext, or an authenticated-KEM construction like
     HPKE's auth mode.
   - **`shared-key!`** (see "Shared symmetric keys") derives the same key
     on both sides with no exchange. With a KEM, one side must first send
     the other a ciphertext: a small handshake, whose result is then kept
     in the vault as before.
   - **Noise KK's `ss` token** is a static-static DH. Post-quantum Noise
     variants are different handshakes, not a swapped primitive.
2. **"The kid is the key" no longer holds.** A kid URN embeds a 32-byte
   Curve25519 key today, so `lookup` rebuilds the key from the kid alone.
   PQ public keys (1,184–1,952 bytes) are too large for that. PQ kids are
   a hash of the key, e.g. `urn:signet:pk:xwing:<base64url(SHA-256(pk))>`,
   and the full key comes from somewhere else: the vault, a directory,
   or the message itself. That affects `lookup`, box's kid slots, and
   chain blocks' `:next-key`. **0.8.0's lookup design should allow for
   kids that do not contain their key**, even before any PQ suite exists.
3. **Hybrid, not replacement.** Combine a classical and a PQ component, so
   the result stays secure if either holds, as TLS's X25519MLKEM768 and
   libsodium's X-Wing do for key exchange. For signatures, a hybrid carries
   both an Ed25519 and an ML-DSA signature, and verification requires
   both.
4. **Sizes grow a lot.** Compared with 32-byte keys and 64-byte signatures
   today: a PQ box header gains about 1.1 KB (the X-Wing ciphertext) plus
   the sender authentication, and a hybrid signature is about 3.4 KB. That
   is roughly 50 times larger per signature, which matters most for
   chains (one signature per block).
5. **Urgency differs.** Key exchange first: boxes and sessions recorded
   today can be decrypted later ("harvest now, decrypt later").
   Signatures are less urgent, since forging one needs a quantum computer
   when it is verified. The exception is long-lived signed objects:
   chains, stored envelopes.

### Distributing large PQ keys (discussed 2026-09-23)

Large keys are fine once per relationship. A directory is an
optimisation, not a requirement.

1. **Self-certifying kids.** A PQ kid is a hash of the key, so a key sent
   inside a message verifies itself: the receiver checks
   `SHA-256(key) = kid`, and a substituted key fails. That gives the same
   guarantee as today's "the kid is the key", in two steps. Which kids are
   *trusted* is still the valid/verified question, and later a policy
   decision point's.
2. **Exchange once, then send only the kid.** After the first exchange the
   receiver keeps the full key on the vault's public side (a registry from
   kid to full key). Later messages carry only the 32-byte kid. This is why
   0.8.0's vault needs that public registry: lookup can no longer rebuild a
   key from its kid.
3. **KEM once, then shared keys.** A KEM box pays about 1.1 KB of
   ciphertext on every message. Running the key exchange once to establish
   a shared symmetric key (`shared-key!`, kept in the vault) makes later
   messages as small as today's. A PQ key exchange plus stored shared keys
   gives both post-quantum protection and small messages.
4. **Endorse new PQ keys with the existing identity.** During the
   transition the Ed25519 identity key signs the new PQ key, which binds
   it to an identity people already trust, without a directory.

Exceptions to "once per relationship":

- **Chains** create a fresh ephemeral key per block. A PQ ephemeral
  signing key costs about 5 KB per block (a 1,952-byte key plus a
  3,309-byte signature). Chains need their own PQ design, for example
  hybrid blocks, or a scheme that does not create a signing key per block.
- **First contact:** encrypting to a new recipient needs their PQ public
  key *before* the first message. It has to arrive first, through an
  earlier message, a key-exchange round trip, or a directory. That is no
  different from today, when the sender needs the recipient's kid.

**Directories** help with first contact and avoid re-sending keys. They
can also become a trust anchor (for example with key transparency), but
that is a policy question, not a cache.

### Suites (as in "Algorithm agility")

Each suite still names the whole protocol, because the header layout,
kid resolution and sender authentication change with it:

| Suite | Key exchange | Sender authentication | KDF | AEAD |
|---|---|---|---|---|
| box v2 (today) | X25519 static-static | implicit in the DH | HKDF-SHA-256 | ChaCha20-Poly1305 |
| box v3 (proposed) | X25519 static-static | implicit in the DH | HKDF-SHA-256 | AEGIS-256 + key commitment |
| box v4 (post-quantum) | X-Wing encapsulation | hybrid signature (Ed25519 + ML-DSA) or an authenticated KEM | HKDF-SHA-256 | AEGIS-256 (or ChaCha20-Poly1305) |
| envelope v2 | — | hybrid signature (Ed25519 + ML-DSA) | — | — |

The AEAD column changes independently of the PQ question: the same
AEADs serve classical and post-quantum suites.

**First step:** box v4's key exchange with X-Wing. It is the urgent part,
libsodium 1.0.22 has it today, and the JDK has ML-KEM for a JCA
provider. Hybrid signatures come after, as they need ML-DSA through
nacljc (libsodium has none), or through the JDK or Bouncy Castle.

## Future: names for keys

Raised 2026-09-23, **not for 0.8.0**. Kids are global, self-certifying
identifiers, but people want to say "Bob". A later version should let
callers find keys by name, and do it in a way that fits trust and policy
rather than a flat lookup table:

- **Names are local, kids are global.** In SDSI/SPKI terms, "Bob" means
  *my* Bob: a name in my namespace, bound to a kid. Linked names compose:
  "Alice's Bob" is the key Alice's namespace binds to "Bob". This avoids
  a global naming authority and fits Zooko's triangle (names that are
  human-readable and secure, but local).
- **Bindings are signed assertions,** not store entries: a naming
  assertion (issuer kid, name, subject kid, validity) as a signed EDN
  envelope. Resolving a name is then a verification that returns evidence
  (which assertions, from whom, valid until when), with the same valid /
  verified / authorized distinction as everything else: a correctly
  signed binding from an issuer you do not trust resolves to nothing.
- **Local petnames first:** the simplest form is my own unsigned binding
  of "Bob" to a kid on the vault's public side. Signed, shareable naming
  assertions (SDSI/SPKI-style) come next.
- **stroopwafel:** naming assertions are facts, and authorization rules
  can refer to names ("members of Alice's group may …"). That makes name
  resolution a natural part of the policy decision point rather than a
  separate lookup.
- **X.509 at most as an import:** reading an X.509 certificate's binding as
  a naming assertion for interop, never as signet's own model.
- Names never replace kids on the wire or in signatures: they resolve to
  kids, and kids are what gets verified.

## Future: persistence and password unlocking

Raised 2026-09-23, **not for 0.8.0**; to be discussed. An encrypted vault
becomes much more useful once it can be saved (a persistent atom, or an
SSH-key-style file), with only ciphertext ever on disk. Unlocking it with
a human password is a long-standing weak spot in many designs. Topics:

- **Password to key:** a memory-hard key derivation function, Argon2id
  (libsodium `crypto_pwhash`; not in the JDK, but in Bouncy Castle). Its
  parameters are stored with the vault so they can be raised later. With
  low-entropy passwords, this step is what resists offline guessing of a
  stolen file.
- **Key layering:** the password unlocks a random vault master key, and
  the master key encrypts the secrets. Changing the password rewraps one
  key, and several unlock methods can wrap the same master key: a
  password, the OS keychain, a hardware token, a recovery key.
- **The file format is a suite,** versioned and authenticated, so the key
  derivation and cipher can change.
- **Unlock lifetime:** per operation, per session, or until a timeout
  (like ssh-agent). While unlocked, the master key sits in protected
  memory (the `:sodium` provider).
- **Recovery:** a recovery key, or deliberately none.
- **Alternatives to passwords:** the OS keychain or Secure Enclave, or a
  hardware token (FIDO2 hmac-secret), which avoid low-entropy passwords.

## Prior art: how libsodium's author uses the pieces

Researched 2026-09-25 in Frank Denis's (jedisct1) repositories. The
question was whether he built a handle or enclave layer himself, or only
supplied the pieces. **Answer: the pieces, plus single-purpose tools that
each assemble a few of them. There is no general layer where code holds
only references** [source].

- **The principle is stated, but not built.** libsodium-doc
  (`helpers/memory_management.md`): `sodium_mprotect_noaccess` "can be
  used to make confidential data inaccessible except when needed for a
  specific operation". That is nacljc's no-access-outside-calls model and
  this vault. In his own projects, `sodium_mprotect_noaccess` appears only
  in the docs, never in code [source: GitHub code search, owner jedisct1].
- **The same page recommends two things we don't do yet:**
  - `sodium_stackzero()` after a batch of sensitive operations, since
    secrets are copied into registers and onto the stack during use even
    when they are stored in locked pages;
  - disabling core dumps (`setrlimit(RLIMIT_CORE, …)`) outside
    development, plus encrypted or disabled swap and no hibernation.
    Memory locking is "defense-in-depth … not a complete solution".
- **minisign (`src/minisign.c`, `get_line.c`) is password unlocking end
  to end:**
  - echo off (termios), and the password read straight into
    `sodium_malloc` memory;
  - scrypt writes its output into another guarded buffer, and the secret
    key is XOR-decrypted in place, also in `sodium_malloc` memory;
  - a BLAKE2b checksum detects a wrong password; every buffer is freed
    with `sodium_free`.

  This is option 3 in docs/08's password notes ("read the password into
  guarded memory"). It is a short-lived command-line process, with no
  no-access protection between uses.
- **turbocrypt (his newer file tool) uses our two-layer key design:** a
  random key in a key file, optionally protected with an Argon2 password.
  "Changing a key file's password doesn't change the encryption key
  inside it" (its `docs/safety.md`). It also uses fixed suites (Argon2,
  AEGIS, HCTR2, TurboSHAKE) "with no insecure options", as in "Suites"
  here.
- **libhydrogen** has a key exchange "based on the Noise protocol" (N,
  KK, XX, NK), but returns the session keys to the caller as plain arrays
  (`hydro_kx_session_keypair { rx, tx }`). signet 0.9.0 keeps them in the
  vault instead.
- **blobcrypt's example** keeps the key and stream state in
  `sodium_malloc` memory. **encpipe** takes passwords on the command line
  or from a file: convenience over hygiene.
- **cpace and spake2-ee** are his password-authenticated key exchanges
  (PAKEs) on libsodium. They are the natural choice if signet ever needs
  sessions authenticated by a password rather than static keys.

**Follow-ups from this:**
1. nacljc: call `sodium_stackzero` after each operation that reads a
   secret (it clears a fixed amount of stack; measure the cost).
2. signet or nacljc: a helper that disables core dumps
   (`setrlimit(RLIMIT_CORE, 0)` over FFI), and a README note on startup
   hygiene: no core dumps, encrypted or no swap, no hibernation.

## Future: enclave tiers (hardware unlocks, software works)

Discussed 2026-09-25, after 0.9.0. Not planned for a release yet.

**The observation.** Hardware enclaves are slow and narrow.
- A TPM or a PIV smartcard or YubiKey takes tens to hundreds of
  milliseconds per signature, is rate-limited, and sits on a slow bus.
- They mostly offer P-256, P-384 and RSA; the Secure Enclave offers only
  P-256. Ed25519 and X25519 are rare (recent YubiKey PIV firmware).
- They have a handful of key slots.

Network HSMs (AWS CloudHSM, KMS) are faster but still costly per call, so
they push bulk work back to the application: KMS `GenerateDataKey` hands
out the plaintext data key, and all message and stream encryption happens
in ordinary heap memory. The root key is protected; the working keys are
not.

signet's handle model is PKCS#11's in spirit:

| PKCS#11 | signet |
|---|---|
| object handle | `KeyHandle` |
| slot / token | vault id → provider |
| `C_Sign`, `C_DeriveKey` (derived keys stay in the token) | `vault/sign`, `shared-key!`, `hkdf-pair!` |
| `CKA_SENSITIVE`, `CKA_EXTRACTABLE=false` | session entries refuse export; `export-secret` needs the acknowledgement |
| session objects | session entries |
| `C_Login` | unlock (planned) |

The difference is that signet offers fixed suites instead of a menu of
mechanisms (see "Suites"). It can afford to keep *every* operation behind
handles because its fast enclave is in-process: libsodium guarded memory
makes each operation cheap. That boundary is weaker than hardware. Guard
pages, `mlock` and no-access-outside-calls stop accidental reads,
over-reads, swap and core dumps, but not an attacker who runs code inside
the process.

**The design: three tiers.**

| Tier | Holds | Operations |
|---|---|---|
| Hardware root (TPM, PIV card, Secure Enclave, FIDO2 key, HSM) | the root identity, unlock factors | rare: unlock, endorse |
| Local guarded enclave (`:sodium`) | vault master key, working keys, session keys | everything hot |
| Heap | public keys, handles, ciphertexts | no secrets |

- **Unlock.** At startup a single hardware operation unwraps the vault
  master key straight into the local enclave: a P-256 ECDH with a TPM,
  the Secure Enclave or a PIV card, FIDO2 `hmac-secret`, YubiKey
  challenge-response, or a keychain release. Then no hardware calls until
  the next unlock. Each factor wraps its own copy of the master key (the
  layering in "persistence and password unlocking"; password input
  options are in docs/08). Hardware algorithms such as P-256 appear only
  in the wrapping suite, never in the working API.
- **Moving keys down a tier never touches the heap.** A working key
  unwrapped by a stronger enclave lands directly in the local one as a new
  handle (decision 8: moving a secret to another enclave yields a new
  handle). This is KMS's envelope pattern without KMS's plaintext data key
  in application memory.
- **Endorsement, for identities bound to hardware.** A non-exportable
  identity is a slow P-256 key, so it should not sign every request. It
  signs, once, an endorsement of a fast Ed25519 working key in the local
  enclave, with an expiry (the pattern of SSH certificates and WebAuthn
  attestation). signet already has the mechanism: a **capability chain**
  whose root is the hardware key and whose next block delegates to the
  working key. Verifiers check back to the hardware root with
  `chain/verify {:root hardware-kid}` (verified = the expected root).
- **The hot path** (sessions, box, shared keys, signing) runs in the local
  enclave with Ed25519 and X25519.

**What the provider protocol needs for this.**
- **Capabilities.** Each provider declares its algorithms, operations and
  rough cost (a PIV card: P-256 sign and ECDH, around 10 per second). The
  vault routes by capability and never sends hot operations to a slow
  tier by accident; an unsupported operation fails loudly
  (`::unsupported-operation`), with no silent fallback.
- **Operations as protocol methods,** not only `-with-material`. An
  out-of-process or hardware enclave never lends its material, so sign,
  ECDH/DH, unwrap-into-another-enclave, HKDF and AEAD must be methods the
  provider implements (docs/08 phase 2 already anticipates this).
- **Non-25519 kids,** such as `urn:signet:pk:p256:…`, for hardware roots
  and wrapping keys.

**Candidate providers,** in a plausible order:
1. `:agent`: a separate process over a Unix socket, like ssh-agent (the
   password never enters the application).
2. `:pkcs11`: binds any PKCS#11 module over FFI, which makes every
   existing HSM and smartcard a signet enclave. Test against SoftHSM.
3. `:secure-enclave` / `:tpm` / `:fido2`: unlock factors and endorsement
   roots.

## Open questions

1. ~~Handle shape~~ **Settled** (decision 7).
2. ~~Default vault~~ **Settled** (decision 8).
3. ~~Sessions timing~~ **Settled**: right after 0.8.0 (decision 9).
4. ~~`:memory-encrypted`~~ **Not in 0.8.0** (decision 11). It becomes
   worth more with persistence and password unlocking: to be discussed
   (see "Future: persistence and password unlocking").
5. ~~Chain tokens~~ **Settled**: keep the bearer model for 0.8.0
   (decision 12).
6. ~~Export guard~~ **Settled**: an explicit acknowledgement is required
   (decision 10).
7. ~~secp256k1~~ **Settled**: `:memory` provider only (decision 13).
8. ~~Shared symmetric keys~~ **Settled**: stateless only; ChaCha20-Poly1305
   with key commitment (decision 14).
8a. ~~The vault's two sides~~ **Settled** (decision 15).
9. **AEGIS-256 as an opt-in suite** (RFC 10032; review 2026-09-23). It has
   a 256-bit key, a 256-bit nonce ("no practical limits" for random
   nonces) and a 256-bit tag, with ~2^128 key commitment unless the
   attacker controls the associated data. libsodium has had it since 1.0.19
   (nacljc's minimum), and libsodium.js since 0.7.13. Bouncy Castle 1.86
   and the JDK do not have it, so it would be provider-specific. Proposal:
   box v3 = X25519 + HKDF-SHA-256 (directional) + AEGIS-256 with a random
   32-byte nonce + key commitment, offered where the provider has it
   (nacljc on native libsodium). The JCA backend refuses it with
   `:unsupported-suite`. Caveat: libsodium's software AES forces lookup
   tables on WebAssembly (`softaes.c`: `#if defined(__wasm__) … #define
   FAVOR_PERFORMANCE`), so libsodium.js AEGIS is not constant-time in the
   browser today [source]. Likely to be fixed upstream. Once it is
   constant-time on every provider signet supports, v3 can become the
   default, with v2 still accepted.
10. **Key commitment on the ChaCha20-Poly1305 path** (box v2 and `seal`).
    Poly1305 is not key-committing: one ciphertext can be valid under two
    keys. That matters most for `unbox` with several candidate keys (no
    `:to` slot). Proposal: a short commitment in the header, e.g.
    `:commit = HMAC-SHA-256(k_msg, "signet/commit")` (truncated), checked
    in constant time before decrypting. It works on every backend,
    independently of AEGIS. It changes the header, so it is a new suite
    (v3 for ChaCha, or folded into the AEGIS suite).
11. **Algorithm agility: suites, not knobs.** Lessons from JOSE/JWT (`alg`
    chosen by the message: `alg: none`, key confusion) versus PASETO, age,
    WireGuard and TLS 1.3 (few fixed suites, versioned):
    - One identifier names the whole combination of algorithms. Box's `:v`
      *is* the suite id; there is no separate `:alg` knob per primitive.
    - The suite id is in the authenticated header (the AEAD's associated
      data), so it cannot be changed in transit.
    - **The receiver decides** what it accepts: `unbox` takes an allowlist
      of suites (default: the current, non-deprecated ones). Unknown or
      disabled gives `{:valid? false :error :unsupported-suite}`. The
      message names its suite but never decides whether it is acceptable.
    - Defaults are visible: results report `:suite`, a function lists the
      provider's supported suites, and a default changes only in a release
      whose CHANGELOG says so. Old suites stay readable while accepted,
      then are deprecated, then refused, each step documented.
    - Known-answer vectors per suite, run on every provider that claims it.
    - The same pattern covers what comes next: signatures already carry
      the algorithm in the kid URN, a post-quantum hybrid (X25519 + ML-KEM)
      would be box v4, and sessions bind the full Noise protocol name into
      the transcript (an AEGIS session would be a signet-specific name).
12. **Post-quantum** (see "Post-quantum suites"): PQ kids resolve through
    the vault's public registry after a key has been carried once in a
    message (a directory is an optimisation); what format carries the key
    the first time, and how is an Ed25519 endorsement of a PQ key
    represented? Sender authentication in box v4: a hybrid signature, or an
    authenticated KEM? Where does ML-DSA come from, given libsodium has
    none: the JDK, Bouncy Castle, or a future libsodium?
13. **Enclave tiers** (see "Future: enclave tiers"): how does a provider
    declare its capabilities and cost, and how does the vault route by
    them? What is the endorsement block format, so that a hardware-rooted
    identity verifies with plain `chain/verify`? Which provider comes
    first: `:agent` or `:pkcs11`?

## Decisions so far (2026-09-23)

1. **Naming convention:** `!` means the call writes state that outlives it.
   Reads such as the clock, randomness and the environment are documented
   and get no `!`. `!` never means "may throw". `Impure:`, `Throws …` and
   `Never throws …` docstring lines; `check-` for validators.
2. **The twin rule:** a function that could benefit from registering comes
   in two versions. `fn` returns the registerable elements, extras under
   `:signet/register`. `fn!` registers them and returns the rest. When the
   element is the primary result, `fn!` returns it as well.
3. **`sign-edn`:** the pure version always takes an explicit key or handle.
   The key-less convenience exists only as `sign-edn!`.
4. **Conversions and `raw-shared-secret`:** pure only, with no `!` twins.
5. **`register!`** only registers; it no longer sets defaults.
6. **This note:** handles and a vault as the direction for secrets, with
   the refinement that secrets are born in the vault. The details are open
   (see above).

### Settled 2026-09-23 (vault design session)

7. **Handles are typed records naming their vault.** A `KeyHandle` record,
   `{:type :signet/key-handle :kid … :vault <vault-id>}`. Operations check
   the type, so a key record or a plain map cannot stand in for a handle.
   A handle is an immutable value, and the vault id is a *name* (a
   keyword), not an object reference. So a handle can be printed,
   serialised, sent, and survives restarts.
8. **The vault id routes the operation.** A registry maps vault ids to
   providers (enclaves). Each operation resolves its vault from the
   handle's `:vault` at call time; an unknown id throws `::unknown-vault`,
   never a fallback. `:default` is the default vault id, and
   explicit-vault arities exist for tests and isolation. The first
   enclave is the current runtime (`:memory`). Later ones (`:sodium`, an
   agent, a keychain, WebCrypto, an HSM) need no API change: a handle
   naming them routes there. Moving or copying a secret to another enclave
   yields a new handle with the new vault id; the old handle keeps
   referring to the old copy until it is destroyed. The same kid may live
   in several vaults.
   - **A handle is a reference, not a credential.** Anyone can build a
     handle for a kid. Whether a key may be used is decided by its enclave:
     the process boundary for `:memory`, the enclave's own policy later
     (an agent asking the user, or a policy decision point such as
     stroopwafel's). That is where "authorized" eventually meets the vault.
9. **Sessions move onto vault handles right after 0.8.0**, as their own
   release, to keep 0.8.0 reviewable. Until then session keys stay in the
   state map, wiped after use as today.
10. **Exporting a secret requires an explicit acknowledgement**, e.g.
    `(export-secret h {:i-understand :exposes-secret})`. Without it the
    call throws. It is cheap enforcement that stands out in grep and in
    review ("take the gun away").
11. **`:memory-encrypted` is not in 0.8.0.** It stays a listed provider,
    to be reconsidered together with persistence and password unlocking.
12. **Chain tokens keep the bearer model in 0.8.0.** The open token's
    `:proof` is held locally as a handle and exported explicitly when the
    token is sent. A possession-proof redesign belongs with the
    post-quantum chain design.
13. **secp256k1 keys live in the `:memory` provider only** (Bouncy Castle,
    JVM only; libsodium has no secp256k1; the keys serve wallet and MPC
    interop).
14. **Shared keys (`seal`) are stateless only** in 0.8.0: a fresh random
    salt per message, with counters left to sessions. The AEAD is
    ChaCha20-Poly1305 with key commitment, the same construction as box
    v3's ChaCha variant; AEGIS-256 follows as a suite where providers have
    it.
15. **The vault has two sides indexed by the same kid.**
    - The **public side** holds public keys: everyone's (peers' and your
      own). It can be shown, exported, and synced to a directory.
      `(lookup kid)` answers from it, falling back to parsing the kid
      (which works for today's 25519 kids).
    - The **secret side** holds private keys, and only those you hold.
      `(handle kid)` answers only if the secret side has the key. Bytes
      leave only through `export-secret` with the acknowledgement.
    - For your own keys both sides have an entry under the same kid (for
      25519 the public half can be derived, so storing it is optional). For
      peers only the public side does. Post-quantum kids are key hashes,
      so their full public keys must be on the public side, even for your
      own keys.
    - Keeping the sides apart keeps trust levels apart: "I know this public
      key" is weaker than "I hold this identity", and a peer's key can
      never be mistaken for one of yours.
    - Keys enter the public side only through an explicit `register!`. A
      key carried in a message is registered only after its kid is verified
      (`SHA-256(key) = kid`) and only when the caller asks, so untrusted
      input cannot grow memory.
16. **Symmetric-key ids are key-derived through HKDF** (`"signet/shared/v1/kid"`),
    not a plain hash of the key. A plain hash of a key derived from a
    password would let an observer test guesses offline. Independent HKDF
    outputs keep the id unrelated to the encryption and MAC keys. And
    unlike a hash of both kids, only holders can compute it, so it does
    not reveal who talks to whom.
17. **Key records are deprecated when sessions move onto handles**, in the
    release after 0.8.0, not removed in 0.8.0 (2026-09-24). In 0.8.0 they
    stay the raw layer: sessions still use them and SSH import returns
    them. Handles are the documented, recommended API.

