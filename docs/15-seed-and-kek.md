# One seed, many keys: derivation, storage, and a KEK

Status: **design and research, 2026-10-24; not built, no spike.** KMS facts
are from AWS's documentation read that day (links at the end), marked
*verified*; everything else is marked *documented* (a standard, from
memory) or *unverified*. Background: docs/14 ("Several keys from one
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

- **The seed is the HKDF pseudo-random key.** 32 random bytes. RFC 5869
  (§3.3) allows skipping HKDF-Extract when the input is already a uniformly
  random key of hash length (documented). So the seed *is* PRK.
- **Each key is HKDF-Expand(seed, label, length)**, with HMAC-SHA-256:

  ```
  T(1) = HMAC(seed, label ‖ 0x01)
  T(2) = HMAC(seed, T(1) ‖ label ‖ 0x02)        ; when more than 32 bytes
  label = "signet/seed/v1/<identity-name>/<alg>/<index>"
  ```

- **Lengths per algorithm** (ECDSA scalars use FIPS 186-5's method with
  64 extra bits, d = (c mod (n−1)) + 1, so no retry loop; documented):

  | Key | Output | HMAC calls |
  |---|---|---|
  | Ed25519 seed | 32 bytes, used as is | 1 |
  | X25519 | 32 bytes (clamped by the library) | 1 |
  | P-256, secp256k1 | 40 bytes, reduced to a scalar | 2 |
  | P-384 | 56 bytes, reduced | 2 |

- **`index`** gives rotation without a new seed: index 1 is the next key.

**Why not BIP32/SLIP-0010.** Their master step is HMAC-SHA512 with the
fixed key `"Bitcoin seed"` (or a per-curve string) and the **seed as the
message**, and hardened child derivation puts the parent private key in
the message too (documented). With the seed in the message, a KMS HMAC key
cannot hold it. Interop with wallets that expect BIP32 paths would need
BIP32 itself, locally; this scheme is for signet's own identities.

**In signet today** (verified in the source): `-hkdf` runs
Extract-then-Expand over an entry or bytes; nacljc wraps libsodium's
`crypto_kdf_hkdf_sha256_extract` and `_expand` separately. An
expand-only operation on a seed entry is the small addition.

## Where the seed lives

1. **In the vault file**, as an entry (guarded memory while unlocked,
   ciphertext on disk). Simple; the seed is as safe as the vault password
   or recovery key.
2. **Offline only**: written down after the keys are imported, then
   destroyed. Formats: a BIP39-style word list (the 32 bytes as words; only
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
- **Limit**: `Decrypt` returns the seed. The rule controls *when* it can be
  unwrapped, not what happens after; derivation runs locally in guarded
  memory, and the seed is destroyed afterwards.

### B. KMS HMAC key as the seed

The seed is imported into a KMS `HMAC_256` key; derivation is
`GenerateMac(HMAC_SHA_256, label ‖ 0x01)` (and a second call for T(2)).
The result is byte-identical to the local derivation.

Verified in AWS's documentation:

- HMAC keys **accept imported key material**, and AWS states that for
  HMAC (and asymmetric) keys "importing creates compatible and
  interoperable keys that operate within and outside of AWS".
- Imported HMAC key material must match the key spec's length: `HMAC_256`
  takes **32 bytes**, which is the seed. Wrapping for import:
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
  derived private key: the permission *is* the identity. Treat it like
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

- **Access**: a dedicated slot with PIN policy *always* and touch policy
  *always* (a device change, Frank's call), while everyday slots keep a
  cached PIN. Every derivation needs the PIN and a touch.
- **Alternative**: FIDO2's `hmac-secret` extension, per credential and with
  touch, as age-plugin-fido2 and systemd-cryptenroll use it (documented).
  It returns a secret to the host: a KEK, not an in-device KDF.
- **Limit**: as in A, the seed is unwrapped into guarded memory for the
  derivation.

### Comparison

| | Seed leaves the KEK holder | "May derive" is | Audit | Works offline |
|---|---|---|---|---|
| Vault file | yes, into guarded memory | the vault password | no | yes |
| A. KMS KEK | yes, into guarded memory | `kms:Decrypt` + context | CloudTrail | no |
| B. KMS HMAC seed | **never** (derived keys do) | `kms:GenerateMac` on one key | CloudTrail | no (the offline backup does) |
| C. YubiKey KEK | yes, into guarded memory | PIN + touch on one slot | none on device | yes |

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

1. Local: derive Ed25519, P-256 and secp256k1 keys from a test seed with
   HKDF-Expand; check determinism and the scalar reduction against known
   vectors.
2. KMS: create an `HMAC_256` key with origin `EXTERNAL`, import the test
   seed, call `GenerateMac` on a label; pass when it equals the local
   `T(1)`. Then T(2).
3. KMS: import a derived Ed25519 key into an `ECC_NIST_EDWARDS25519` key;
   pass when `GetPublicKey` gives the local kid.

## Open decisions (Frank's)

- The scheme: HKDF-Expand with the seed as PRK and labelled outputs, as
  above (no BIP32 for signet identities).
- The default home of the seed: vault file, offline, or a KEK (A, B, C).
- B's one-key-per-identity rule and who holds `kms:GenerateMac`.
- A dedicated YubiKey slot with PIN and touch *always* for C.

## Sources

- Importing key material, supported key types: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
- Encrypting key material (HMAC lengths, wrapping algorithms): https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
- HMAC keys in AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html
- GenerateMac: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
