# Password unlocking and vault persistence

Status: **decisions taken 2026-09-27** (see the end). Slice 1, the
password-derived key handle, is built (`signet.password`, 0.10.0); the
vault file (slice 2) is not. Builds on docs/07 ("Future: persistence and
password unlocking"), docs/08 (password-derived keys as handles; getting
the password in) and nacljc 0.4.0/0.5.0 (`argon2id`, `wrap-secret`,
`unwrap-secret`).

## Goal

A vault that can be **saved to a file and reopened with a password**, with
only ciphertext ever on disk, and with secret bytes kept out of the
Clojure heap the whole way (on the `:sodium` provider): typed password ->
key -> master key -> identity keys, each a secret or a handle.

## The key layers

    password (bytes, imported into a secret and wiped)
      -> Argon2id(password, salt, limits)          = the password key (a secret)
      -> unwraps the vault master key              = MK (a secret: 32 random bytes)
      -> MK decrypts the vault's entries           = the identity keys (secrets)

- **The master key** is random and never changes for a vault. Changing the
  password rewraps MK only; the entries are untouched.
- **More than one way to unlock** later: each unlock method (a password, a
  recovery key, the OS keychain, a FIDO2 key, a hardware tier from docs/07)
  wraps its own copy of MK. The file holds a list of them.
- **Argon2id** from nacljc (`argon2id`), cost `:moderate` by default
  (3 passes, 256 MiB, about a second), stored with the salt so it can be
  raised later.

## The vault file: a suite

An EDN map, canonical (cedn); the header is the AEAD's associated data, so
nothing in it can be changed without failing decryption:

```clojure
{:type    :signet/vault-file
 :v       1                                ; the suite: Argon2id13 + ChaCha20-Poly1305 + this layout
 :id      :default                          ; the vault id it was saved from (informational)
 :unlock  [{:method    :password
            :salt      #bytes "…16 bytes…"
            :opslimit  3
            :memlimit  268435456
            :nonce     #bytes "…12 bytes…"
            :wrapped   #bytes "…MK encrypted under the password key…"}]
 :nonce   #bytes "…12 bytes…"
 :entries #bytes "…the secret and public sides, encrypted under MK…"}
```

- **What is saved:** the secret side (identity keys: Ed25519 seeds, X25519
  secret keys, with their kids), the public side, and the default signing
  key. **Not saved:** session entries (a session does not outlive the
  process) and shared keys (they can be derived again).
- **The public side is encrypted too:** which peers a vault knows is itself
  worth hiding.
- **Writing:** to a temporary file, then an atomic rename; mode 0600.

## Secrets stay off the heap: a nacljc prerequisite

Saving means encrypting each secret under MK; loading means decrypting
into secrets. Today nacljc's AEAD takes a secret **key** but its
plaintext and its output are byte arrays, so the secret bytes would pass
through the heap during save and load. That breaks the model.

**nacljc 0.5.0 would add key wrapping inside guarded memory:**
- `(wrap-secret k nonce s aad)`: ChaCha20-Poly1305 of secret `s`'s bytes,
  read in place, under key `k` (a secret); returns ciphertext bytes (safe
  to store).
- `(unwrap-secret k nonce ct aad)`: decrypts straight into a new secret;
  the plaintext never exists as a byte array. `::auth-failed` for a wrong
  key (so a wrong password is detected by the AEAD tag, not by a stored
  password hash).

With these, the whole chain stays in guarded memory. On the JCA backend
(`:memory` provider) secrets are heap bytes anyway, so the same code path
works with byte arrays.

## Lock and unlock

- **A locked vault** has its public side (`lookup`, `public-key` work) but
  an empty secret side; operations that need a secret throw
  `::vault-locked`. Handles stay valid values: they work again after
  unlocking.
- **`unlock!`** takes the password (bytes; imported into a secret and
  wiped), derives the password key, unwraps MK, and loads the entries into
  the provider. A wrong password gives `::bad-password` (the AEAD failed);
  nothing is loaded.
- **`lock!`** destroys every secret in the vault and MK. Session entries
  are destroyed too, so open sessions in that vault end (`::destroyed-key`
  on their next message).
- **Unlock lifetime** (later): lock after a timeout of inactivity, like
  ssh-agent.

## API sketch

```clojure
(vault/create-file! :default "vault.edn" password {:limits :moderate}) ; new, empty, saved
(vault/open-file! :default "vault.edn")          ; registers the vault, locked
(vault/unlock! :default password)                ; password: bytes, wiped
(vault/save! :default)                           ; writes the file (atomic, 0600)
(vault/lock! :default)
(vault/change-password! :default old new)        ; rewraps MK only
(signet.password/password-key! password {:limits :moderate}) ; built (slice 1):
(signet.password/seal h plaintext)                           ; a key handle for
(signet.password/open h-or-password sealed)                  ; seal/open
```

Names follow the convention: `!` for functions that write the vault, the
file or an argument (the password array they wipe).

## Getting the password in

As in docs/08: a byte array (the UTF-8 of what was typed), which the vault
imports into a secret and wipes. A `String` cannot be wiped, so accepting
one is a documented convenience at most. Later: a TTY reader in nacljc
that reads straight into guarded memory (minisign's approach), and an
agent (docs/07) for applications that should never see the password.

## What it protects against

- **A stolen vault file:** only Argon2id stands between the thief and the
  keys: a weak password stays weak, but each guess costs about a second
  and 256 MiB (at `:moderate`). A recovery key or a hardware factor avoids
  low-entropy passwords altogether.
- **Tampering with the file:** the header is authenticated; a changed salt,
  cost or entry fails decryption.
- **Not:** code running in the process while the vault is unlocked (the
  audience note in docs/07), or a keylogger capturing the password.

## The recovery key (optional)

Decided 2026-09-27: **optional, off by default.**

- **Created only when asked for:** `create-file!` with
  `{:recovery-key? true}`, or `add-recovery-key!` later on an unlocked
  vault (it needs the master key).
- **Never stored itself.** It is 32 random bytes. The file holds only one
  more `:unlock` entry, `{:method :recovery-key :nonce … :wrapped …}`: the
  master key wrapped under a key derived from the recovery key by **HKDF,
  not Argon2id** (256 random bits cannot be guessed, so no slowdown is
  needed, and unlocking with it is instant).
- **Shown once, by the application.** signet returns it once, as the one
  deliberate exit of a secret for a human: as **bytes** (so the caller can
  wipe them after displaying or printing), behind the acknowledgement
  `{:i-understand :exposes-secret}`, like `export-secret`. The format is
  made for people: Crockford base32 in groups (no 0/O, 1/I/l confusion)
  with a checksum, so a typo is caught before any decryption, e.g.
  `SIGNET-RK1-7K3M-QX9P-2ABF-…-C4` (the prefix names the format, like age's
  `AGE-SECRET-KEY-1…`).
- **Using it:** `unlock-with-recovery-key!` (bytes, wiped), then
  `reset-password!`, which rewraps the master key under a new password
  without the old one. `remove-recovery-key!` revokes it (its only wrapped
  copy is gone); `add-recovery-key!` replaces it.
- **Security:** the recovery key is full access, with no Argon2id cost: it
  must be kept offline. There is no backdoor: without the password and
  without a recovery key, the keys are gone, and the docs say so.

## Decisions (2026-09-27)

1. **nacljc 0.5.0 first:** `wrap-secret` / `unwrap-secret`, so secrets never
   touch the heap during save and load.
2. **Order:** the password-derived key handle first (`password-key!`, seal
   and open with a password), then the vault file on top.
3. **Saving: both,** explicit `save!` by default, and an `:auto-save`
   option when opening a file (write whenever a key is generated,
   imported or destroyed).
4. **The libsodium backend only** for password features; on the JCA
   backend they throw a clear `::unsupported` error.
5. **The recovery key is in v1, optional and off by default** (above).
