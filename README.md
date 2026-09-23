# Signet

Ed25519 / X25519 signing and encryption for Clojure with EDN-native
envelopes. Canonical EDN ([cedn](https://github.com/franks42/canonical-edn))
is the signed bytes and [uuidv7](https://github.com/franks42/uuidv7.cljc)
provides request ids. Also provides capability chains (`signet.chain`),
sender-authenticated encryption (`signet.encryption`), Noise_KK sessions
(`signet.session`) and SSH key import (`signet.ssh`).

Runs on the JVM and babashka. ClojureScript is not implemented yet.

## Crypto backends

`signet.impl` selects the backend once, when it loads: the JVM system
property `signet.backend`, then the environment variable `SIGNET_BACKEND`,
then the default `jca`. Both backends produce byte-identical signatures,
keys and ciphertexts.

| Backend | Namespace | Needs | Notes |
|---|---|---|---|
| `jca` (default) | `signet.impl.jvm` | a JDK | No native dependency. Deriving a public key from a seed does not work on babashka. |
| `sodium` | `signet.impl.sodium` | libsodium >= 1.0.19 (`brew install libsodium`), [sodium.cljc](../sodium.cljc) (local for now), JDK 25+ with `--enable-native-access=ALL-UNNAMED`, or bb >= 1.13.220 | The full test suite also passes on babashka. |

```bash
clojure -M:test:sodium      # the :sodium alias adds sodium.cljc and selects the backend
SIGNET_BACKEND=sodium bb …  # on babashka, with ../sodium.cljc/src on the classpath
```

## Development

```bash
bb test:jvm   bb test:jvm-sodium   bb test:bb-sodium   bb smoke
bb lint       bb fmt
```
