# Secrets by reference: handles and a vault

Status: **draft for discussion** (2026-09-23). Nothing here is
implemented. It is **planned for the release after 0.7.0**. 0.7.0 ships
the naming and purity changes and redacted printing as a stop-gap.
"Decisions so far" at the end lists what is already settled. The rest is
proposed and marked as open.

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
| `dh` handle their-public-key | shared secret, **kept in the vault** as a new handle (see "Derived secrets") |
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
  wiping matter most here. Open: whether it goes into 0.7.0 or right after.

### Derived secrets

`dh` / `edh` outputs, HKDF outputs and session keys are secrets too. The
rule: **a secret derived from a vault secret stays in the vault** and is
returned as a handle. The pure core (`impl`, `mix-key!`) still works on
bytes, inside the provider.

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
3. **Sessions on vault handles:** in 0.7.0 or next (open).
4. **Later:** `:memory-encrypted` where native is unavailable, `:webcrypto`
   for signet's ClojureScript side, then agent, keychain and HSM providers.

## Open questions

1. Handle shape: a plain map, or a record with a type tag? Should the
   vault name be in the handle, or implied by where the handle is used?
2. One global default vault, or an explicit vault always, with the default
   only in the convenience (`!`) functions?
3. Sessions in 0.7.0, or right after?
4. `:memory-encrypted`: worth building, given that `:sodium` covers the JVM,
   bb and nbb and WebCrypto covers the browser? Its remaining use is the
   JCA backend without libsodium.
5. Chain tokens: keep `:proof` as exportable bearer material (today's
   design), or redesign so a token proves possession without carrying the
   secret, for example through a signature from the holder's handle?
6. Should `export-secret` require an explicit acknowledgement argument, for
   example `(export-secret handle :i-understand)`, or is the name enough?
7. secp256k1 (Bouncy Castle) keys live in the `:memory` provider only.
   Acceptable?

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
