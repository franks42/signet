# One seed, many keys: derivation, storage, and a KEK

Status: **design and research, 2026-10-24; not built, no spike.** KMS facts
are from AWS's documentation read that day (links at the end), marked
_verified_; everything else is marked _documented_ (a standard, from
memory) or _unverified_. Background: docs/14 ("Several keys from one
seed"), docs/13 (KMS), the tutorial outline (chapter 7).

## Why

One random seed from which every key of an identity is derived (Ed25519,
X25519, P-256, P-384, secp256k1) gives:

- **one backup** for all keys, and a restore test that is exact: derive
  again, get the same kids;
- **deliberate placement**: each derived key is imported where it should
  live (guarded memory, SoftHSM, the YubiKey, KMS);
- **one point of compromise**: the seed. Where it lives, and who may use it
  to derive, is the whole question. That is what a key-encryption key
  (KEK) with its own access rules answers.

## The derivation scheme

Design rule: **the seed is only ever used as an HMAC key**, never as an
HMAC message. That single choice makes the derivation runnable inside KMS
(below) and is why the scheme is plain HKDF-Expand rather than BIP32 or
SLIP-0010.

- **The seed is the HKDF pseudo-random key.** 64 random bytes. RFC 5869
  (§3.3) allows skipping HKDF-Extract when the input is already a uniformly
  random key of hash length (documented). So the seed _is_ PRK.
- **Each key is HKDF-SHA-512-Expand(seed, label, length)**, at most 64
  bytes, which is a single HMAC truncated to the length:

  ```
  out   = first length bytes of HMAC-SHA-512(seed, label ‖ 0x01)
  label = "signet/seed/v1/<identity-name>/<alg>/<index>/<counter>"
  ```

  (Revised 2026-10-24 from HMAC-SHA-256 with a 32-byte seed. With SHA-256,
  P-256 and P-384 needed a second block, T(2) = HMAC(seed, T(1) ‖ label ‖
  0x02), which puts the secret T(1) into an HMAC _message_: KMS can still
  compute it, but nacljc's HMAC takes only public messages. With SHA-512,
  every key is one HMAC, one KMS `GenerateMac` call.)
- **Per algorithm**:

  | Key              | Output                                           | Accept when |
  | ---------------- | ------------------------------------------------ | ----------- |
  | Ed25519          | 32 bytes, the seed of `crypto_sign_seed_keypair` | always      |
  | X25519           | 32 bytes (clamped by the library)                | always      |
  | P-256, secp256k1 | 32 bytes, a big-endian scalar d                  | 0 < d < n   |
  | P-384            | 48 bytes, d                                      | 0 < d < n   |

- **ECDSA scalars by rejection, not reduction** (revised 2026-10-24 from
  FIPS 186-5's "64 extra bits, then mod n"). Reduction is arithmetic on a
  secret, and libsodium has no bignum for these curves, so it would run on
  the heap. Rejection needs only a validity check, which the curve library
  that computes the public key does anyway, on a pointer (libsecp256k1's
  `secp256k1_ec_seckey_verify`, for example). On rejection, the counter
  goes up and the HMAC runs again. The chance is about 2⁻³² for P-256 and
  negligible for the others, so the retry path is tested by injection, not
  by finding a real vector.
- **`index`** gives rotation without a new seed: index 1 is the next key.
  **`counter`** starts at 0 and only moves on rejection.

### The same derivation in guarded memory

The local derivation is the same function as KMS's, not an emulation:
`GenerateMac` is "the standard, raw HMAC defined in RFC 2104" (verified,
AWS API reference), and libsodium's `crypto_kdf_hkdf_sha512_expand` (or
`crypto_auth_hmacsha512`) is the same RFC 2104 HMAC-SHA-512 (documented).
Both exist in the libsodium in use (1.0.22; verified in its headers).

- **Sodium provider**: the seed is a 64-byte entry; derivation is an
  operation that writes the output into a new entry (phase 0's secret
  results), the seed and the output never leaving guarded memory. A
  shorter key is the same output read with a shorter length: pointer plus
  length, no copy through Clojure.
- **KMS provider**: the same operation as one `GenerateMac(HMAC_SHA_512)`
  on an `HMAC_512` key holding the imported seed (64 bytes, the key spec's
  length; verified). The output comes back over TLS into guarded memory.
- **What is missing** (verified in the source): nacljc wraps
  `crypto_kdf_hkdf_sha256_*` only, as extract-then-expand, and its
  `hmac-sha-256` returns a public tag. Needed: an expand-only
  HKDF-SHA-512 in nacljc, secret in, secret out (a nacljc change, Frank's
  approval), and the operation in signet's provider protocol.
- **Checks before KMS**: libsodium against an independent HMAC-SHA-512
  (JCA's `HmacSHA512`, on the JVM) on fixed seeds and labels; RFC 4231's
  HMAC-SHA-512 vectors for the primitive (RFC 5869 has SHA-256 vectors
  only). Then the KMS spike compares with the same vectors.
- **ECDSA** additionally needs the curve library (docs/14's open P-256
  decision; libsecp256k1 for secp256k1) to validate the scalar and give the
  public key from the pointer. Ed25519 and X25519 need nothing beyond
  libsodium.

**Why not BIP32/SLIP-0010.** Their master step is HMAC-SHA512 with the
fixed key `"Bitcoin seed"` (or a per-curve string) and the **seed as the
message**, and hardened child derivation puts the parent private key in
the message too (documented). With the seed in the message, a KMS HMAC key
cannot hold it. Interop with wallets that expect BIP32 paths would need
BIP32 itself, locally; this scheme is for signet's own identities.

## Where the seed lives

1. **In the vault file**, as an entry (guarded memory while unlocked,
   ciphertext on disk). Simple; the seed is as safe as the vault password
   or recovery key.
2. **Offline only**: written down after the keys are imported, then
   destroyed. Formats: a BIP39-style word list (the 64 bytes as words; only
   the encoding is borrowed, not BIP39's PBKDF2 seed stretching) or Shamir
   shares (SLIP-0039, k of n). Documented, not designed here.
3. **Wrapped under a KEK**, so using the seed needs a separately authorized
   act. Three variants follow.

### A. KMS symmetric key as the KEK

The seed is wrapped with KMS `Encrypt` under encryption context
`{"purpose" "signet/seed" "identity" "<root kid>"}`; the blob is stored
anywhere (the vault file, S3).

- **Access**: `kms:Decrypt` with condition
  `kms:EncryptionContext:purpose = signet/seed`, granted to a separate role
  (for example one requiring MFA). Everyday roles cannot unwrap; every
  unwrap is in CloudTrail.
- **Limit**: `Decrypt` returns the seed. The rule controls _when_ it can be
  unwrapped, not what happens after; derivation runs locally in guarded
  memory, and the seed is destroyed afterwards.

### B. KMS HMAC key as the seed

The seed is imported into a KMS `HMAC_512` key; derivation is
`GenerateMac(HMAC_SHA_512, label ‖ 0x01)`, truncated to the key's length.
The result is byte-identical to the local derivation.

Verified in AWS's documentation:

- HMAC keys **accept imported key material**, and AWS states that for
  HMAC (and asymmetric) keys "importing creates compatible and
  interoperable keys that operate within and outside of AWS".
- Imported HMAC key material must match the key spec's length: `HMAC_512`
  takes **64 bytes**, which is the seed. Wrapping for import:
  `RSAES_OAEP_SHA_256` (or `_SHA_1`, or `RSA_AES_KEY_WRAP_*`).
- `GenerateMac` computes "the standard, raw HMAC defined in RFC 2104", on
  messages of 1 to 4096 bytes, and AWS says the raw result can "implement
  HMAC-based algorithms such as key derivation functions"; HMAC keys "can
  also be used as secure Key Derivation Functions (KDFs), especially in
  applications that require deterministic keys".
- HMAC keys can be multi-Region keys; they do not support automatic
  rotation (irrelevant here: rotating the seed means new keys anyway).

What it gives:

- **The seed never leaves KMS after import.** "May derive" is exactly the
  `kms:GenerateMac` permission on that one key (with `kms:MacAlgorithm` as
  a condition key), separate from every other permission. Deny
  `kms:VerifyMac` too; it is not needed.
- **An offline backup still derives the same keys locally**, so KMS is
  not a single point of loss: lose the AWS account, keep the identity.
- **Multi-Region** replication covers availability.

Limits and open points:

- **The derived key comes back to the caller** (it must, to be imported
  elsewhere). Whoever holds `kms:GenerateMac` on the key can obtain every
  derived private key: the permission _is_ the identity. Treat it like
  the seed.
- No condition key restricts the message (unverified: none found), so the
  permission cannot be limited to some labels. One KMS HMAC key per
  identity keeps identities apart.
- Whether CloudTrail records the `Message` of `GenerateMac` (the label;
  not secret either way): unverified.
- Importing needs RSA-OAEP to wrap the seed for KMS. libsodium has no RSA,
  so that step runs in BouncyCastle (JVM) or OpenSSL: the seed passes
  through a library that does not use guarded memory. A one-time ceremony,
  but it should be said.

### C. YubiKey as the KEK

PIV has no symmetric wrap, but a PIV X25519 (firmware 5.7+) or P-256 key
can be the recipient of a box: the seed is sealed to the slot's public key
and unsealing needs that slot's private key.

- **Access**: a dedicated slot with PIN policy _always_ and touch policy
  _always_ (a device change, Frank's call), while everyday slots keep a
  cached PIN. Every derivation needs the PIN and a touch.
- **Alternative**: FIDO2's `hmac-secret` extension, per credential and with
  touch, as age-plugin-fido2 and systemd-cryptenroll use it (documented).
  It returns a secret to the host: a KEK, not an in-device KDF.
- **Limit**: as in A, the seed is unwrapped into guarded memory for the
  derivation.

### Comparison

|                  | Seed leaves the KEK holder  | "May derive" is              | Audit          | Works offline                |
| ---------------- | --------------------------- | ---------------------------- | -------------- | ---------------------------- |
| Vault file       | yes, into guarded memory    | the vault password           | no             | yes                          |
| A. KMS KEK       | yes, into guarded memory    | `kms:Decrypt` + context      | CloudTrail     | no                           |
| B. KMS HMAC seed | **never** (derived keys do) | `kms:GenerateMac` on one key | CloudTrail     | no (the offline backup does) |
| C. YubiKey KEK   | yes, into guarded memory    | PIN + touch on one slot      | none on device | yes                          |

## Importing derived keys into their targets

`derive-into!` (tutorial decision D8): derive one key and import it into
a target provider in one step, so the derived bytes exist only in guarded
memory and inside the target.

- **Guarded memory** (`:sodium`): an entry, directly.
- **SoftHSM / PKCS#11**: `C_CreateObject` or `C_UnwrapKey` with the bytes
  from guarded memory (yubikey-sodium's generic PKCS#11 client).
- **YubiKey PIV**: `ykpiv_import_private_key` from guarded memory; a
  device change (slot and what it overwrites named first). The key is
  then marked as imported, not generated, in PIV attestation.
- **KMS**: `GetParametersForImport`, wrap with RSA-OAEP (see the limit in
  B), `ImportKeyMaterial`. For asymmetric keys KMS takes the private key
  only and derives the public key (verified).
- **Check after every import**: the target's public key gives the expected
  kid; otherwise fail and destroy.

## Spike plan (when AWS credentials are at hand)

1. Local: derive Ed25519, P-256 and secp256k1 keys from a test seed;
   libsodium against JCA's HmacSHA512 on the same seeds and labels;
   determinism; the rejection path by injection.
2. KMS: create an `HMAC_512` key with origin `EXTERNAL`, import the test
   seed, call `GenerateMac` on the labels; pass when every result equals
   the local derivation.
3. KMS: import a derived Ed25519 key into an `ECC_NIST_EDWARDS25519` key;
   pass when `GetPublicKey` gives the local kid.

## Open decisions (Frank's)

- The scheme: HKDF-SHA-512-Expand with a 64-byte seed as PRK, labelled
  outputs, rejection for ECDSA scalars (no BIP32 for signet identities).
- The nacljc addition: expand-only HKDF-SHA-512, secret in, secret out.
- The default home of the seed: vault file, offline, or a KEK (A, B, C).
- B's one-key-per-identity rule and who holds `kms:GenerateMac`.
- A dedicated YubiKey slot with PIN and touch _always_ for C.

## Sources

- Importing key material, supported key types: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
- Encrypting key material (HMAC lengths, wrapping algorithms): https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
- HMAC keys in AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html
- GenerateMac: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
