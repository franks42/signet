(ns ^:no-doc signet.impl
  "INTERNAL — not part of signet's public API. These functions take raw
   keys and caller-chosen AEAD nonces; misusing them (e.g. reusing a nonce)
   breaks confidentiality and integrity. Use signet.sign, signet.chain,
   signet.encryption and signet.session instead, which create and manage
   nonces and ephemeral keys internally. Public only because signet's own
   namespaces call them.

   Crypto backend facade. signet's namespaces call these 18 functions; they
   forward to the backend selected once, when this namespace loads:

     :jca     signet.impl.jvm    — Java JCA (default; no native dependency)
     :sodium  signet.impl.sodium — libsodium via babashka.ffi (JVM and bb)

   Selection, in order: the JVM system property signet.backend, then the
   environment variable SIGNET_BACKEND, then :jca. Reading them is the one
   impure step, and it happens once, at load; after that the backend is
   fixed for the life of the process. Selecting :sodium when libsodium or
   nacljc is unavailable fails loudly at load instead of falling back
   to JCA.

   Both backends produce byte-identical output
   (test/signet/backend_parity.clj), so switching changes no signature, key
   or ciphertext.")

(def backend
  "The selected backend: :jca or :sodium."
  (keyword (or (System/getProperty "signet.backend")
               (System/getenv "SIGNET_BACKEND")
               "jca")))

(def ^:private backend-ns
  (case backend
    :jca    'signet.impl.jvm
    :sodium 'signet.impl.sodium
    (throw (ex-info (str "Unknown signet backend " backend " (expected jca or sodium)")
                    {:backend backend}))))

(try
  (require backend-ns)
  (catch Throwable t
    (let [root (loop [e t] (if-let [c (ex-cause e)] (recur c) e))]
      (throw (ex-info (str "signet backend " backend " failed to load"
                           (when (= :sodium backend)
                             " — needs libsodium >= 1.0.19 and nacljc on the classpath (alias :sodium)")
                           ". Cause: " (ex-message root))
                      {:backend backend :ns backend-ns
                       :cause-class (str (class root)) :cause (ex-message root)}
                      t)))))

(defn- f
  "The selected backend's function named sym."
  [sym]
  (or (some-> (ns-resolve backend-ns sym) deref)
      (throw (ex-info (str backend-ns " has no " sym) {:backend backend}))))

(def generate-ed25519-keypair (f 'generate-ed25519-keypair))
(def ed25519-seed->public-key (f 'ed25519-seed->public-key))
(def sha-256 (f 'sha-256))
(def ed25519-sign (f 'ed25519-sign))
(def ed25519-verify (f 'ed25519-verify))
(def generate-x25519-keypair (f 'generate-x25519-keypair))
(def x25519-private->public-key (f 'x25519-private->public-key))
(def ed25519-pub->x25519-pub (f 'ed25519-pub->x25519-pub))
(def ed25519-seed->x25519-private (f 'ed25519-seed->x25519-private))
(def ed25519-keypair->x25519-keypair (f 'ed25519-keypair->x25519-keypair))
(def x25519-dh (f 'x25519-dh))
(def hmac-sha-256 (f 'hmac-sha-256))
(def hkdf-sha-256 (f 'hkdf-sha-256))
(def destroy-material! (f 'destroy-material!))
(def split-material (f 'split-material))
(def random-bytes (f 'random-bytes))
(def chacha20-poly1305-encrypt (f 'chacha20-poly1305-encrypt))
(def chacha20-poly1305-decrypt (f 'chacha20-poly1305-decrypt))
