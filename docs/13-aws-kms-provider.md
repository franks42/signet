# AWS KMS as a signet provider

Status: **research, 2026-10-24; not built, no spike yet.** Everything below
is from AWS's documentation (links at the end), read on that date; nothing
was run against AWS. Claims are marked *verified* (read in the docs or in
signet's source) or *unverified*.

## Why

Hardware tiers (docs/07, docs/12) keep keys out of the application, but a
YubiKey or a local HSM brings its own operations: backups, a second
device, what happens when it is lost. A managed cloud key service takes
those over: AWS KMS keeps keys in its HSMs, replicates them across Regions
on request, and logs every use (CloudTrail). The question here is what of
signet it can carry, and how the AWS credentials it needs stay out of the
application.

AWS CloudHSM (dedicated HSM clusters) is not the target: it is priced for
large organisations (about $1.60 per HSM-hour, a third-party figure; two
HSMs recommended for production), must be reached inside a VPC, and its
Ed25519 support is a vendor PKCS#11 mechanism on one instance type in
non-FIPS mode only. If it were ever wanted, it speaks PKCS#11, and
yubikey-sodium's generic PKCS#11 provider is the starting point.

## What KMS offers, against signet's operations

| signet (Provider op) | AWS KMS | Notes |
|---|---|---|
| `-sign`, Ed25519 | **yes**: key spec `ECC_NIST_EDWARDS25519`, `Sign` with `ED25519_SHA_512` and `MessageType: RAW` | Added 2025-11-07, all Regions (verified). **Messages up to 4096 bytes** (verified). `ED25519_PH_SHA_512` is HashEdDSA: a different signature (unusable for signet). |
| `-x25519-dh` | **no** | `DeriveSharedSecret` is ECDH on NIST P-256/384/521 (and SM2 in China) only; not Ed25519, not secp256k1, no X25519 (verified). |
| `-hkdf`, `-aead-*` (ChaCha20-Poly1305) | no | KMS has no HKDF and no ChaCha20. |
| `-hmac` | yes, with HMAC keys (`HMAC_256`, `GenerateMac`/`VerifyMac`) | The tag is returned to the caller; KMS cannot derive a key into a new KMS key, so HMAC does not help keep derived secrets inside. |
| `-wrap` / `-unwrap` | **yes**: symmetric `Encrypt`/`Decrypt` (AES-256-GCM, up to 4096 bytes, encryption context as AAD) | The fit for vault files (below). The ciphertext format is KMS's own (not decryptable outside KMS). |
| `-public-key` | `GetPublicKey` (DER SubjectPublicKeyInfo) | Gives signet's kid. |
| `-generate!` | `CreateKey` | 5 per second; a management call, not a hot path. |
| `-import!` | yes: asymmetric keys (all but ML-DSA) accept imported material | Existing signet identities could move into KMS (verified). |
| `-export` | never | Fails closed (`:unsupported`). |
| `-destroy!` | `ScheduleKeyDeletion`, 7 to 30 days' wait; or `DisableKey` | Not immediate: the provider must say which it did (refuse, or disable and schedule). |
| secp256k1 (signet's BouncyCastle path) | `ECC_SECG_P256K1`, `ECDSA_SHA_256` | DER signatures; low-s normalization not documented (unverified). |
| post-quantum signing | `ML_DSA_44/65/87`, `ML_DSA_SHAKE_256` | A possible PQ path (docs/07's open PQ topic). |

**Redundancy and backups:** multi-Region keys (asymmetric and HMAC
included) share key ID and key material across Regions; each replica works
on its own if the others are unavailable (verified). That is the
operational win: no backup procedure for the key itself.

**Cost and limits** (verified unless noted): $1 per key per month; the
pricing page's example rate for ECC signing is $0.15 per 10,000
requests; asymmetric calls are outside the free tier. ECC operations
(Sign, Verify, DeriveSharedSecret) share 1,000 requests per second per
account and Region, by default (adjustable). Latency per call: not
measured (unverified; a network round trip).

## What this means for signet

1. **A KMS key is a sign-only identity**, a root-tier key in D1's terms
   (yubikey-sodium's design review): like a YubiKey slot without X25519.
   The provider implements `-sign`, `-public-key`, `-has?`, `-kids`,
   `-alg` and throws `:unsupported` for the rest; phase 0 makes that
   clean (a provider without `Lending`, `test/signet/operations_test.clj`).
2. **No encryption identity in KMS.** Box, shared keys and Noise sessions
   need X25519; that identity stays in a software vault (`:sodium`).
3. **The 4096-byte limit meets `sign-edn`.** `sign-edn` signs the canonical
   bytes of the whole envelope, payload included (verified in
   `signet.sign`), so a larger envelope cannot be signed by KMS. HashEdDSA
   would change the signature. The same limit exists for the YubiKey agent
   (512-byte frames): hardware providers want signet to sign a small,
   framed digest of the payload. That is a wire-format decision (the
   open "where is signet's framing applied" question), not a provider
   detail.
4. **Byte-identical signatures** with libsodium are expected (FIPS 186-5
   EdDSA is RFC 8032 Ed25519, deterministic) but **unverified**: the
   first thing a spike checks.
5. **Kids:** signet's kid comes from the public key (`GetPublicKey`); the
   provider maps it to the key ARN (an alias or tag per key, or a local
   table).

## Two integrations, in order of value

### 1. KMS-sealed vault files

A new unlock method `:kms` next to `:password` and `:recovery-key`
(`signet.vault.file`, docs/10): the vault's master key is wrapped by a KMS
symmetric key, with the vault id and file path as encryption context.

- Identity keys stay in signet's guarded memory: everything keeps working,
  X25519 included.
- The wrapping key lives in KMS: never exported, replicated across Regions
  if wanted, every unlock in CloudTrail, revocable by IAM/key policy, and
  (encryption context) bound to this vault file.
- Backups reduce to copying the vault file anywhere (S3, a laptop).
- Cost: unlocking needs the network and AWS credentials; the master key
  comes back over TLS into guarded memory: standard envelope encryption.
  Under phase 0 that is an `-unwrap` whose key is a KMS key: the
  provider's `Decrypt` result is adopted into an internal entry.

This covers the "no backups, no redundancy to run" goal for every key a
vault holds.

### 2. A KMS signing provider

For one or a few long-lived identity keys that should never exist outside
an HSM (a root authority for `signet.chain`, a release-signing key).
Each signature is a KMS call. A related KMS feature: `GenerateDataKeyPair`
with `ECC_NIST_EDWARDS25519` returns a new Ed25519 key pair with the
private key encrypted under a KMS key: software keys born already backed
up (unverified for Ed25519 beyond the announcement's "data key pairs").

## AWS credentials: the agent approach

KMS calls are HTTPS requests signed with SigV4, so whoever makes them
holds AWS credentials, and those are secrets. Two layers:

**Where the credentials live: an agent** (docs/12's design, as built in
yubikey-sodium's ykagent for the PIN). The agent process holds the
credentials; the application holds handles and talks to the agent over a
Unix socket. The agent enforces its own policy (which keys, which
operations) and audits; IAM and the key policy are a second, independent
layer, and CloudTrail a second audit log. The application process never
sees AWS credentials.

**How the agent gets them, without long-lived keys:**

- **IAM Roles Anywhere with the YubiKey** (preferred). Roles Anywhere
  exchanges a signature by an X.509 certificate's key for temporary
  credentials; AWS's `aws_signing_helper` supports PKCS#11 and names
  YubiKeys (verified). So: PIV certificate on the YubiKey → temporary
  credentials (about an hour, configurable) → KMS. AWS access is tied to
  the physical key and its PIN; nothing long-lived on disk. Open
  (unverified): Roles Anywhere likely wants an RSA or P-256 key (not
  Ed25519), so a new PIV key and certificate in a slot such as 9a (a
  device change, Frank's call); the trust anchor can be your own CA
  certificate (no AWS Private CA needed); PIN handling at each refresh
  is the same question as ykagent's (agent holds it, or touch).
- **IAM Identity Center (SSO)**: short-lived, easy, but its credential
  cache is a file every process of the user can read. Weaker.
- **Instance or task roles** (EC2, ECS, Lambda): no credential handling at
  all, when signet runs inside AWS.

**Client code on babashka:** `awyeah-api` (Cognitect's aws-api for bb;
maintenance unclear, last push about a year ago per one listing), or a
small SigV4 implementation of our own (about 100 lines over bb's
http-client). With our own, the AWS secret key could be a vault entry and
the SigV4 HMAC chain run as operations: that needs an "HMAC into a new
entry" variant of `-hmac` (today's returns the tag).

## Prior art: the AWS Encryption SDK

AWS's client-side library for KMS-backed encryption (read in its developer
guide, 2026-10-24; all *verified* in the docs unless marked). Not a
candidate dependency: AES-GCM and NIST curves only, no Clojure or bb
binding (the Java one works from JVM Clojure), and against the
libsodium-everywhere goal. Worth studying for its design, which solved
several of signet's problems first.

**What it does.** Envelope encryption: each message gets a fresh data key;
the payload is encrypted locally; the data key is encrypted by one or more
*wrapping keys* and the encrypted copies travel in the message. Decrypting
needs any one wrapping key. The message format is published and all
language implementations interoperate.

**Interfaces, in layers:**

- **Keyring**: generates, encrypts and decrypts data keys; that is all it
  does. Kinds: AWS KMS (symmetric or RSA KMS keys, with "discovery"
  variants that accept any KMS key on decrypt), multi-Region KMS, KMS
  Hierarchical, KMS ECDH, raw AES, raw RSA, raw ECDH, and the
  **multi-keyring** (encrypts the data key under every member keyring;
  decrypts with whichever member can). Custom keyrings implement a
  published interface (on-encrypt / on-decrypt over a materials object).
- **Cryptographic materials manager (CMM)**: sits between the SDK and the
  keyring, assembles the materials (plaintext and encrypted data keys, the
  signing key), and is the documented hook for policy and caching (the
  caching CMM; the "required encryption context" CMM that refuses encrypt
  requests missing given keys).
- **Encrypt / decrypt**: the application calls these two functions and
  never sees a data key.
- Keyrings and CMMs live in a separate library, the Cryptographic Material
  Providers Library (MPL). The MPL and the newer SDK implementations
  (.NET, Rust, Go) are written in **Dafny** with proofs and transpiled
  (documented in the Rust and Go guides).

**Mechanisms:**

- **Algorithm suites**, not free algorithm choices. The default: AES-256-GCM
  under a key HKDF-derived (SHA-384) from the data key, key commitment,
  and an ECDSA P-384 signature. The random message ID (32 bytes in format
  v2) is what makes reusing a data key across messages safe. Weaker suites exist only for
  compatibility.
- **Encryption context**: string key-value pairs, not secret, bound to the
  ciphertext as AAD, stored in plaintext in the header (and, with KMS,
  visible in CloudTrail). The SDK returns it on decrypt; the application is
  expected to check that the context it wants is a subset.
- **Signatures with ephemeral keys.** A signing suite generates a key pair
  per message, puts the public key in the encryption context
  (`aws-crypto-public-key`, so it is bound to the encrypted data key) and
  discards the private key. Purpose: someone allowed only `kms:Decrypt`
  could otherwise build new messages under a data key they unwrapped. It
  proves the message came from someone allowed to encrypt; it does **not**
  identify a sender. The docs say it has no value when the keyring cannot
  separate encryptors from decryptors (raw AES, raw RSA, ECDH,
  Hierarchical).
- **Key commitment** (since 2.0, the default commitment policy
  `RequireEncryptRequireDecrypt`): the header carries a commitment string
  derived from the data key (HKDF-SHA-512), checked before decryption.
  Reason given: a crafted message with several encrypted data keys could
  hold *different* data keys for different wrapping keys, so two readers
  would decrypt one ciphertext to two plaintexts. Cost: 30 bytes.
- **Framed bodies**: plaintext in equal frames (sequence number, a
  deterministic IV per frame, final frame marked `FF FF FF FF`), so
  streaming, truncation and reordering are detected.
- **Hierarchical keyring**: a KMS-protected *branch key* stored in
  DynamoDB is decrypted once (one KMS call), cached locally for a set time
  (the cache-limit TTL), and each message's data key is wrapped under a key
  derived from it with a 16-byte random salt. 10,000 encrypts in one TTL
  window cost one KMS call instead of 10,000. Branch keys rotate; old
  versions still decrypt.
- **KMS ECDH keyring**: sender's KMS key pair (NIST curves only) plus
  recipient's public key → `DeriveSharedSecret` → a counter-mode KDF
  yields 64 bytes: 32 for a commitment key, 32 for the wrapping key. Close
  to signet's box, but on P-256/384/521.

**What signet can take from it:**

1. **Integration 1 is the standard pattern.** The `:kms` unlock method is a
   KMS keyring around the vault's master key; signet's unlock entries
   (`:password`, `:recovery-key`) are already a multi-keyring. The design
   to copy: every unlock entry wraps the same master key, any one opens
   the file, and adding a KMS key in a second Region is one more entry.
2. **Encryption context, made checkable.** Signet's AAD today is canonical
   bytes the caller builds (the vault file binds its whole header). A
   named, structured context that decrypt *returns* and that a policy can
   *require* (the required-context CMM) is a cleaner interface for
   `-wrap`/`-unwrap` with a KMS key, whose context also lands in
   CloudTrail.
3. **Key commitment: check signet's formats.** I read
   `signet.vault.file`: the body is ChaCha20-Poly1305 under a key HKDF'd
   from the master key and a fresh salt, with the header as AAD. Poly1305
   does not commit to the key, and the file has several unlock entries,
   which is the ESDK's scenario: whoever can write the file could, in
   principle, make the password and the recovery key unlock different
   master keys, under which one body decrypts to different contents. My
   judgement (unverified by experiment): low risk for a single-owner file
   (the writer could simply write a different file), cheap to close: store
   a commitment (an HKDF output of the master key under its own label) in
   the header and check it before decrypting. The same question applies
   to box and shared-key messages once they have more than one recipient.
4. **Suites, not knobs.** Signet already names versions (`:v 1`, HKDF
   labels with `/v1/`); the ESDK's suite IDs plus a commitment policy
   (refuse to decrypt older suites) are the model for retiring an old
   format.
5. **Caching KMS calls, the Hierarchical way.** If a KMS-sealed vault is
   unlocked often, a cached, derived wrapping key with a TTL is the
   pattern, and the TTL is the same idea as signet's auto-lock (docs/11).
6. **Two meanings of "signed".** ESDK signatures prove *authorized to
   encrypt*; signet signatures prove *which identity*. The tutorial should
   say this: a reader coming from AWS will assume the first.
7. **Interop, if ever needed.** Signet could write ESDK messages (the format
   is public), but only with AES-GCM and NIST curves. Not now.

## Spike plan (when credentials are at hand)

Cost: two KMS keys, about $2 a month; short-lived credentials (SSO is fine
for the first round).

1. Create an `ECC_NIST_EDWARDS25519` key; `GetPublicKey`; `Sign` a signet
   envelope's bytes (< 4096) with `ED25519_SHA_512`/`RAW`. Pass: the
   signature is byte-identical to libsodium's for the same key (import a
   known seed into a second key to compare) and verifies with
   `signet.sign/verify`.
2. Latency of `Sign` and `Decrypt` from the laptop (median and tail).
3. A symmetric key: wrap and unwrap a 32-byte master key with an encryption
   context; a changed context must fail.
4. Then, separately: Roles Anywhere with a PIV certificate (needs the slot
   decision).

## Open decisions (Frank's)

- Whether vault files get a `:kms` unlock method (integration 1) first.
- Whether signet signs a framed digest for hardware providers (the
  4096-byte KMS limit, the 512-byte agent frame).
- `destroy!` on a KMS key: refuse, or disable and schedule deletion.
- The credential source: Roles Anywhere with the YubiKey (and which slot),
  or SSO to start.
- Whether vault files (and multi-recipient messages) get a key commitment
  (prior art, point 3).

## Sources

- KMS key spec reference: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
- KMS Sign: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- EdDSA announcement (2025-11-07): https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/
- DeriveSharedSecret: https://docs.aws.amazon.com/cli/latest/reference/kms/derive-shared-secret.html
- Request quotas: https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html
- Pricing: https://aws.amazon.com/kms/pricing/
- Imported key material: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
- Multi-Region keys: https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
- CloudHSM PKCS#11 mechanisms: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html
- CloudHSM FAQs: https://aws.amazon.com/cloudhsm/faqs/
- CloudHSM pricing (third-party calculator): https://www.factualminds.com/tools/aws-cloudhsm-pricing-calculator/
- Roles Anywhere credential helper: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.md
- Credential helper PKCS#11 support: https://aws.amazon.com/about-aws/whats-new/2023/09/iam-roles-anywhere-credential-helper-pkcs-11-modules/
- Cryptographic modules with Roles Anywhere: https://aws.amazon.com/blogs/security/how-to-implement-cryptographic-modules-to-secure-private-keys-used-with-iam-roles-anywhere/
- awyeah-api: https://gittrend.io/repo/grzm/awyeah-api
- Encryption SDK concepts: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html
- Encryption SDK algorithm suites: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html
- Encryption SDK message format: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
- Keyrings: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html
- Hierarchical keyring: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html
- KMS ECDH keyring: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-ecdh-keyring.html
- Encryption SDK languages: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/programming-languages.html
- Rust (Dafny origin): https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/rust.md
- Go: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/go.html
