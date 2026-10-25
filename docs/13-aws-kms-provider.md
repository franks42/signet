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
