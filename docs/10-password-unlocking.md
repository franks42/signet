# Password unlocking and vault persistence

Status: **design proposal, 2026-09-27.** Builds on docs/07 ("Future:
persistence and password unlocking"), docs/08 (password-derived keys as
handles; getting the password in) and nacljc 0.4.0 (`argon2id`, secret
password in, secret key out). Nothing is built yet; the decisions at the
end are open.

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
(vault/password-key! :default password salt limits) ; a password-derived key handle
                                                    ; for seal/open, like signet.shared
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

## Decisions needed

1. **Order:** first the password-derived key handle (`password-key!`,
   seal/open with a password), then the vault file on top of it? Or the
   file directly?
2. **The JCA backend:** password features on the libsodium backend only,
   or also on the JVM through Bouncy Castle's Argon2 (not on bb)?
3. **Saving:** an explicit `save!`, or a vault bound to a file that saves
   itself whenever a key is added or destroyed?
4. **A recovery key** in the first version (a random, high-entropy key
   shown once, as a second unlock method), or later?
5. **nacljc 0.5.0 first:** `wrap-secret` / `unwrap-secret`, so that secrets
   never touch the heap during save and load. (Recommended; the
   alternative is exporting secrets during save and load, which breaks the
   model.)
