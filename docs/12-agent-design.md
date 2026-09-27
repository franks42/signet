# The agent: secrets in a separate process

Status: **design, 2026-09-27; not built.** The `:agent` provider named
in docs/07 ("providers: memory, sodium secure memory, WebCrypto,
agent"), in ssh-agent's shape: the secrets live in another process, the
application holds handles, operations travel over a Unix socket.

## Why

Everything signet does today keeps secrets inside the application's
process. Guarded memory (`:sodium`) keeps them off the heap, but the
process can still reach them: a REPL, a debugger, a heap or core dump,
any code running in the process (the runtime attack surface of docs/07).
Moving the secrets to a separate process changes what a compromise of the
application yields:

| An attacker in the application process can | today | with the agent |
|---|---|---|
| read key bytes | yes (with effort: guarded memory, not a boundary) | **no** |
| copy the keys for later, elsewhere | yes | **no** |
| use the keys while connected | yes | yes, **within the agent's policy** |

The third row is ssh-agent's known limit: whoever can talk to the socket
can ask for operations. The agent's policy (confirmation, per-key rules,
lifetimes, audit) is what narrows it, so policy is part of the design,
not an extra.

The agent process can also be made much harder than an application:
no REPL, no nREPL, little code, `nacljc.process/harden-process!` on by
default there (no core dumps, not dumpable), possibly its own uid. It is
the small, locked-down runtime that docs/07 sketched as a far-future
"policy-gated runtime", in the one place where it matters.

## The prerequisite: operation-level providers

Providers today **lend material**: `(-with-material p kid f)` calls `f`
with the secret, and signet runs the crypto on it. That cannot cross a
process boundary. The provider protocol has to offer **operations**
instead, and a secret result stays inside the provider as a new entry:

| Operation | Input | Returns |
|---|---|---|
| `-sign` | key id, message | signature (public) |
| `-x25519-dh` | key id, peer public key | **new entry id** (the DH output never leaves) |
| `-hkdf` | entry id (ikm or salt), salt/info, lengths, `:secret?` | new entry ids, or public bytes |
| `-hmac` | entry id, data | tag (public) |
| `-aead-encrypt` / `-aead-decrypt` | entry id, nonce, data, aad | ciphertext / plaintext (data, not keys) |
| `-wrap` / `-unwrap` | entry id (key), entry id / ciphertext | ciphertext / new entry id |
| `-argon2id` | entry id (password), salt, limits | new entry id |
| `-generate`, `-import`, `-destroy`, `-export` | as today | as today |

The vault already funnels nearly every use of secret material through a
few internal functions: `sign`, `x25519-dh`, `hkdf-pair!`,
`aead-encrypt`/`aead-decrypt`, `with-internal`, `with-temp-material`,
`argon2id-material`, plus the `with-material` calls in `signet.shared`,
`signet.password` and `signet.vault.file`. So **phase 0** is an inventory
and a reroute: every `with-material` call becomes an operation, the
`:memory` and `:sodium` providers implement the operations locally, and
nothing changes in behavior (the full suite and the backend parity tests
are the check). `with-material` stays only as a provider-internal detail.

This refactor is worth doing without the agent too: it is the same seam
that hardware tiers (docs/07: TPM, Secure Enclave, smartcards, HSMs)
need, since none of them lend key bytes either.

## Phases

### Phase 0: operation-level providers (refactor, no behavior change)

As above. Also the moment to decide which derived values are secret
(new entries) and which are public (returned): HKDF outputs used as keys
are secret; a kid derived by HMAC is public.

### Phase 1: an ssh-agent client provider (sign-only), the quick win

The standard ssh-agent protocol (draft-miller-ssh-agent) signs arbitrary
bytes: for an Ed25519 key, `SSH_AGENTC_SIGN_REQUEST` returns a plain
Ed25519 signature over the data sent. So a provider that speaks it to
`$SSH_AUTH_SOCK` lets signet `sign-edn` with keys held in:

- OpenSSH's `ssh-agent` (keys added with `ssh-add`),
- 1Password's SSH agent (with its own approval prompts),
- other agents that hold Ed25519 keys. (Secretive's Secure Enclave keys
  are ECDSA P-256, not Ed25519, so not these.)

Sign-only: the protocol has no DH, so boxes and sessions stay with other
providers. Small (a binary framing, three message types), immediately
useful, and it proves the operation seam against a real external
process. `vault/register-vault! :ssh (agent/ssh-agent-provider)`; the
vault lists the agent's Ed25519 keys as handles.

### Phase 2: the signet agent

- **Process:** signet itself (bb or JVM) with the `:sodium` provider,
  opening a vault file (docs/10). The server dispatches each request to
  its local vault's operations: the same code on both sides, the client
  being signet with the `:agent` provider.
- **Socket:** a Unix domain socket in `$XDG_RUNTIME_DIR` (Linux) or a
  per-user temporary directory (macOS); directory 0700, socket 0600.
  `SIGNET_AGENT_SOCK` names it, like `SSH_AUTH_SOCK`.
- **Peer check:** the connecting process's uid must match
  (`SO_PEERCRED` on Linux, `getpeereid` on macOS, through FFI in nacljc);
  the pid is logged.
- **Protocol:** nREPL's message model without `eval` (see "Wire
  protocol" below). Typed errors travel as data and are rethrown as
  `ex-info` on the client. Nothing secret is ever sent back; `:export` is
  refused unless the agent's policy allows it (default: never).
- **Handles:** unchanged for the caller. A handle names a kid and a
  vault; the vault's provider is the agent. Session entries and derived
  keys are entries in the agent, referenced by id.
- **Unlocking:** in the agent, never in the application: the agent
  prompts on its own terminal (`nacljc.tty`, docs/11) or through
  pinentry, so the application never sees the password.
- **Lifecycle:** `signet agent start` / `stop` / `status`; the client
  reconnects; a dead agent gives `::agent-unavailable`; entries of a
  disconnected client (its sessions) are destroyed.

### Wire protocol: nREPL's message model, without eval

Discussed 2026-09-27. Three existing shapes are the same pattern, a map
with an operation and an id on a stream, with replies matched by id:

```clojure
;; nREPL
{:op "eval" :code "(+ 1 2)" :id "7" :session "…"}  →  {:id "7" :value "3" :status ["done"]}
;; babashka pod
{:op "invoke" :var "signet.vault/sign" :args "[…]" :id "7"}  →  {:id "7" :value "…" :status ["done"]}
;; the signet agent
{:op "signet/sign" :entry "urn:…" :msg #bytes "…" :id "7" :session "…"}
  →  {:id "7" :sig #bytes "…" :status ["done"]}
```

So the question is not the protocol but **which operations the server
offers.** nREPL with `eval` runs any code: exactly the REPL that docs/07
names as the runtime attack vector, and a request would be a program
(`(dotimes [_ 1e6] (sign …))`), which per-operation policy, confirmation
and audit cannot handle. nREPL whose only operations are signet's is
simply our operation protocol, with one request being one operation of
bounded cost.

**Decision (proposed): the agent speaks nREPL's message model, with only
signet operations.** What that gives:

- framing, message matching by id, and `:status` conventions already
  defined;
- `describe`: clients discover the operations and versions;
- nREPL sessions map to agent clients: when a client's session closes or
  its connection drops, its entries (Noise sessions, derived keys) are
  destroyed;
- existing client libraries on the JVM, bb and nbb, and familiarity for
  Clojure developers.

**Transport: EDN rather than bencode.** Bencode has no keywords, sets or
tagged values, so handles, typed errors and `#bytes` would need an extra
encoding layer. nREPL itself has an EDN transport, and another of our
projects runs an nREPL server in Scittle that speaks EDN directly instead
of bencode, which worked well and is simpler. The plan: the same message
maps, as canonical EDN (cedn), one length-prefixed frame per message. A
bencode transport stays possible (it is a small layer where a library
provides it) if existing tools need it.

**Implementation:** either the nREPL library with an explicit handler
(`nrepl.server/start-server :handler …`, never the default handler), or,
like the Scittle server, a small server loop of our own: read a frame,
look the op up in a map of allowed operations, run the policy, reply.
The second is little code and has no default handler that could bring
`eval` back. Open: whether bb's built-in nREPL server
(`babashka.nrepl`) can run without eval at all; if not, the agent uses
its own loop on bb.

**The guard (a requirement):** a misconfigured nREPL server is remote
code execution for anyone who reaches the socket, the worst failure
available. So:

- the handler, or the dispatch map, is built explicitly from signet's
  operations, never from a default;
- at startup the agent checks itself: `describe` lists exactly the
  expected operations, and `eval`, `load-file`, `interrupt` and any
  unknown op answer `unknown-op`; it refuses to start otherwise;
- the test suite and `bb release-check` run the same check.

**Alternative kept open: the pod message format** (`invoke` with `:var`
and `:args`), which bb and `babashka/pods` clients call natively. Pods
fit a helper process that each client starts; nREPL fits one
long-running server shared by many clients, which is what an agent is.
A pod's describe message can also ship code for the client to evaluate,
which a client must never accept from the agent.

### Phase 3: policy (where the agent earns its keep)

- **Per key:** allowed operations (sign only; DH only; no export),
  allowed clients (by uid, later by executable), a lifetime
  (`ssh-add -t`), confirm on each use (`ssh-add -c`: a pinentry dialog
  naming the client and the operation).
- **Per agent:** auto-lock (docs/11) lives here naturally, with system
  events (sleep, screen lock) where the platform offers them.
- **Audit:** an append-only log of operations (time, client, key,
  operation; never data).
- **The PDP seam:** the agent is exactly the point where "may this
  client use this key for this?" is asked, the *authorized* question of
  the trust model. Keep it a function the policy calls
  (`(authorize? request context)`), so stroopwafel's Datalog policy can
  plug in later.

### Later, or not at all

- **Agent forwarding** (as `ssh -A`): risky (anyone with root on the
  remote host can use the keys); not planned.
- **Remote agents** (over TLS, or a Noise_KK session from signet itself):
  possible later; the protocol is transport-independent.
- **Speaking PKCS#11** in either direction (signet as a client of
  PKCS#11 modules, or the agent behind a PKCS#11 front): an open
  question, related to docs/07's hardware tiers.

## Costs and open questions

- **Latency:** a Noise message becomes a few round trips (DH, HKDF,
  AEAD). Unix sockets cost tens of microseconds per round trip: fine for
  signet's uses. Batching operations into one request is possible later.
- **Babashka:** Unix domain sockets are in the JDK since 16
  (`UnixDomainSocketAddress`); whether bb's native image includes them
  needs checking before bb is chosen as the agent's runtime. The JVM
  works either way.
- **nbb/browser:** no Unix sockets in the browser; the browser analogue
  is a browser extension holding the keys (docs/09's second trust path).
- **Windows:** named pipes instead of Unix sockets; out of scope for now.

## Order

0. Operation-level providers (refactor).
1. The ssh-agent client provider (sign-only).
2. The signet agent (process, socket, peer check, protocol, unlocking).
3. Policy (per-key rules, confirmation, lifetimes, audit, the PDP seam).
