# Auto-lock and password input

Status: design 2026-09-27. **Part 1 built** (signet 0.10.0): the
destroy race fix and auto-lock. **Part 2:** `nacljc.tty` built (nacljc
0.6.0), signet accepts secrets as passwords (step 1); password handles
(step 2) next. Two follow-ups to docs/10
(vault files, built in 0.10.0): locking an unlocked vault after a period
of inactivity, and getting a typed password into guarded memory without
it ever being a `String` or a byte array on the Clojure heap. Both feed
the agent (docs/12), where auto-lock and password prompts belong most
naturally.

## Part 1: auto-lock after inactivity

### First: a destroy race to fix (a bug today)

nacljc's `secret-destroy!` refuses a secret that another thread is using
(`::secret-in-use`): no use after free. But the vault's `:sodium`
provider removes the entry from its map *before* it calls
`secret-destroy!`:

```clojure
(-destroy! [_ kid]
  (let [[old _] (swap-vals! secrets dissoc kid)]      ; forgotten first
    (when-let [s (get-in old [kid :secret])]
      (na/secret-destroy! s)                          ; may throw ::secret-in-use
      true)))
```

So `destroy!`, `lock!` or `unregister-vault!` racing an operation on the
same key forgets the secret without freeing it: a live key stays in
guarded memory, unreachable and never wiped, until the process ends. A
timer that locks the vault on its own thread makes this race realistic,
so it is fixed first.

**Fix: a read/write lock per vault** (`ReentrantReadWriteLock` on the JVM
and bb; nbb is single-threaded). Operations that lend material
(`with-material`, `with-internal`, `with-temp-material`) hold the read
side; `destroy!`, `destroy-session!`, `clear!` (lock) and
`unregister-vault!` take the write side, so they wait for operations in
flight and no new one starts meanwhile. Failing-first test: an operation
blocked inside `with-material` on one thread, `lock!` on another; before
the fix the entry is gone and the nacljc audit log shows no `:free`.

Retrying `secret-destroy!` until the use count drops would also work, but
the lock also gives `lock!` a clean "wait for operations in flight"
point, which auto-lock wants anyway.

### Activity

- **The clock:** a monotonic timestamp (`System/nanoTime`) in the vault's
  file state, set on every key use (the one choke point for key use:
  `provider-of`, `with-internal`) and on every write (`changed!`).
  Reading `status` is not activity.
- **Sessions:** a Noise session message uses the vault's session entries,
  so it counts as activity. Locking ends every session (docs/10); a
  long-lived session keeps its vault awake. The alternative, sessions not
  counting, would kill long conversations mid-stream; documented either
  way.
- **`touch!`** (optional): an explicit "the user is still here" for
  applications that know better (a UI event).

### Two mechanisms, both needed

1. **Lazy check:** before each key use, `(lock-due? state now)`; if so,
   lock, then throw `::vault-locked`. This makes the rule exact even if
   the timer is late (a suspended laptop, a busy scheduler).
2. **Background timer:** a daemon thread (`ScheduledExecutorService`; a
   `setTimeout` on nbb) that wakes at the due time and locks. Without
   it, "locked after 15 minutes" is only true at the next call, and the
   keys sit in memory in between, which is what the timeout is meant to
   end. Daemon, so it never keeps the JVM alive; rescheduled on activity
   (or it wakes, finds activity, and sleeps again).

The decision is a pure function, `(lock-due? {:last-used :unlocked-at
:idle-timeout :max-unlocked} now)`, so tests inject the clock and the
scheduler and never sleep.

### Options (on `create!` and `open!`)

```clojure
{:idle-timeout (* 15 60 1000)    ; lock after 15 minutes without key use
 :max-unlocked (* 8 60 60 1000)  ; lock 8 hours after unlocking, used or not
 :on-lock      (fn [vault-id reason] …)   ; reason: :idle, :max-unlocked, :explicit
 :on-dirty     :save}            ; :save (default), :discard, :stay-unlocked
```

- **Unsaved changes when the timer fires.** `lock!` refuses to drop them.
  Saving needs only the master key, not the password, so the default is
  **save, then lock**. `:discard` is for vaults that must not change on
  disk behind the caller's back; `:stay-unlocked` keeps the vault open and
  reports it through `:on-lock` with reason `:dirty` (and retries at the
  next due time). With `:auto-save` the vault is never dirty.
- **`:on-lock`** lets the application react ("vault locked: enter the
  password"). It runs on the timer thread; documented.
- **`status`** gains `:locks-in` (milliseconds, or nil).

**As built:** `:on-lock` is called only when the vault acts on its own:
reasons `:idle` and `:max-unlocked` (it locked), `:dirty` (stayed
unlocked under `:stay-unlocked`) and `:save-failed` (the save before
locking failed, so it stayed unlocked rather than lose keys); an
explicit `lock!` does not call it. Staying unlocked restarts both
periods. Writes count as use. `touch!` was not added (any key use is
activity). The gate is a fair `Semaphore` with a thread-local record of
held gates (bb has no `ReadWriteLock`); a destroy from inside an
operation throws `::destroy-inside-operation`. A `:clock` option injects
the clock for tests.

### Not planned

Locking on system events (sleep, screen lock, user switch) is out of
reach from a portable JVM or bb process. An application that sees such
events calls `lock!` itself. The agent (docs/12) is where this would go
on a desktop.

### Size

One slice: the destroy race (failing-first test), the activity clock,
`lock-due?`, the timer, the options, `status`. Injection checks for each
guard, as usual.

## Part 2: a password reader in nacljc (straight into guarded memory)

### Goal

Today a password reaches signet as a byte array (the UTF-8 of what was
typed), which signet moves into guarded memory and wipes (under
`:sodium`: `secret-import!`, then the array is zeroed). The gap is before
that: how the caller got the bytes. A `String` from `read-line` or
`System.console().readPassword()` (a `char[]`, then encoded) leaves
copies on the heap that cannot be wiped. The reader closes that gap:
keystrokes go from the terminal straight into `sodium_malloc` memory.

### How (`nacljc.tty`, libc through FFI, like `nacljc.process`)

1. Open **`/dev/tty`**, not stdin: it is the terminal even when stdin is
   a pipe (what `readpassphrase(3)`, ssh and minisign do).
2. `tcgetattr` saves the terminal settings; `tcsetattr` switches off
   `ECHO` and `ICANON` (raw mode), so nacljc handles the editing keys
   itself: backspace/DEL, ^U (clear the line), Enter (done), and **^C,
   which becomes `::interrupted`** instead of killing the process with
   echo still off.
3. `read(fd, ptr, 1)`, one byte at a time, **directly into a
   `sodium_malloc` buffer** (readwrite during the read; a fixed maximum,
   e.g. 1024 bytes, `::too-long` beyond it).
4. Copy the exact length into a new nacljc secret, wipe and free the
   buffer, and restore the terminal settings in `finally`.

**Platform details.** `struct termios` differs: `tcflag_t` is 8 bytes on
macOS and 4 on Linux, so `c_lflag` is at offset 24 vs 12; `ECHO` is 0x8
on both, `ICANON` 0x100 (macOS) vs 0x2 (Linux). nacljc treats the struct
as an opaque buffer (sized generously) and changes the flag word at the
platform's offset. glibc has no `readpassphrase`, and `getpass` uses a
static buffer, so nacljc writes the loop itself on every platform.

### API sketch

```clojure
(tty/read-password "Vault password: ")                      ; → a nacljc secret
(tty/read-password "New password: " {:confirm "Again: "})   ; read twice; ::mismatch
(tty/read-password-fd fd)          ; a pipe or file descriptor (scripts, systemd credentials)
```

- The confirmation compares the two secrets with `constant-time-equal?`
  (which takes secrets since nacljc 0.4.0) and destroys the second.
- **No terminal** (an editor-connected REPL, CI, a service) throws
  `::no-tty`. Such programs use `read-password-fd`, or the agent
  (docs/12), which prompts on its own terminal or through pinentry.
- Namespace separate from `nacljc.core`, which binds libsodium only.

### signet: passwords as secrets, and as handles

**Yes, a password is bytes: the UTF-8 encoding of what was typed.** Every
signet function that takes a password (`password-key!`, `open`,
`create!`, `unlock!`, `change-password!`, `reset-password!`,
`unlock-with-recovery-key!`) takes a byte array today. The plan widens
that, step by step:

1. **A nacljc secret is accepted wherever bytes are.** The vault already
   moves a password into the provider as a temporary entry
   (`with-temp-material`), and the `:sodium` provider's `-adopt!` keeps a
   secret as it is, so this is small. Ownership moves to signet: the
   caller's secret is destroyed after use, just as a byte array is wiped
   (the same "consumed" rule, documented in each docstring).

   ```clojure
   (vf/unlock! :default (tty/read-password "Password: "))   ; never on the heap
   ```

2. **A password handle** (the observation from the 2026-09-27 review):
   `(vault/import-password! pw)` moves the password (bytes or a secret)
   into the vault as an entry of kind `:password` and returns a handle,
   and every password-taking function also accepts that handle. The
   password is then a vault secret like any key: code passes a reference,
   the vault lends the material to Argon2id inside the provider.

   Uses: an application that asks once and unlocks several vaults, or
   derives a password key and unlocks a file with the same password,
   without holding the bytes in between.

   The trade-off to document: a password handle that outlives the unlock
   keeps the password in memory, which undoes auto-lock (it can unlock
   again without the user). So `import-password!` is one-use by default
   (the entry is destroyed after the first use), with `{:uses n}` or
   `{:keep true}` as explicit choices, and `lock!` destroys password
   entries along with everything else.

### Limits (documented)

- Keystrokes still pass through the kernel's terminal layer and the
  terminal emulator's memory; a keylogger or a compromised terminal
  sees them.
- **Unicode normalization:** the same password can be typed as different
  bytes (é as one code point or two, depending on the system and input
  method). Argon2id hashes raw bytes, so a password with such characters
  may not open the vault from another system. Normalizing (NFC) needs a
  `String`, which is exactly what the reader avoids. Documented
  recommendation: ASCII passwords, or passphrases of plain words; a
  future option could normalize inside guarded memory for the common
  cases.
- **Later:** pinentry (GnuPG's prompt programs: a GUI dialog that answers
  over a pipe, in the Assuan protocol). nacljc would read the answer into
  a secret the same way. Most useful for the agent, which often has no
  terminal.

### Size

nacljc 0.6.0: `nacljc.tty` (reader, confirm, fd variant; tests with a
pseudo-terminal driven by a child process, as `bb test:process` does for
`nacljc.process`). Then a signet slice: secrets accepted as passwords
(step 1); password handles (step 2) as a second, separate slice.

## Order

1. The destroy race (a bug; failing-first test).
2. Auto-lock.
3. nacljc 0.6.0 `nacljc.tty`, then signet accepting secrets as passwords.
4. Password handles.
