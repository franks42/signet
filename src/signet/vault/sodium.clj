(ns signet.vault.sodium
  "The vault's :sodium provider: secrets in libsodium's guarded memory, via
   nacljc 0.2.0 secrets (sodium_malloc: guard pages, canaries, mlock; no
   access outside a call, read-only during one). Keys are generated
   directly in guarded memory, operations get the nacljc secret itself
   (nacljc reads it in place), and secret results of operations on it (DH
   outputs, derived keys) are nacljc secrets too. So under this provider
   secret bytes never touch the Clojure heap, except through export-secret.

   Needs the libsodium backend (signet.impl/backend = :sodium): the JCA
   backend cannot take nacljc secrets. signet.vault/default-provider picks
   this provider automatically on that backend."
  (:require [nacljc.core :as na]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.vault :as vault]))

(def ^:private ack {:i-understand :exposes-secret})

(defn- public-key-record [alg s]
  (case alg
    :ed25519 (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 (na/ed25519-public-key s))
    :x25519  (key/->X25519PublicKey :signet/x25519-public-key :X25519 (na/x25519-public-key s))))

(defn sodium-provider
  "A provider holding secrets in nacljc secrets (libsodium guarded memory).
   Impure: returns a new, empty provider.
   Throws ex-info {:type :signet.vault/provider-needs-backend} unless signet
   runs on the libsodium backend."
  []
  (when-not (= :sodium impl/backend)
    (throw (ex-info "The :sodium vault provider needs signet's libsodium backend (-Dsignet.backend=sodium)"
                    {:type :signet.vault/provider-needs-backend :backend impl/backend})))
  (let [secrets (atom {})
        store!  (fn [alg s]
                  (let [pub (public-key-record alg s)]
                    (swap! secrets assoc (key/kid pub) {:alg alg :secret s})
                    pub))]
    (reify vault/Provider
      (-generate! [_ alg] (store! alg (na/secret-random 32)))
      (-import! [_ alg secret-bytes]
        ;; secret-import! copies into guarded memory and wipes secret-bytes
        (store! alg (na/secret-import! secret-bytes)))
      (-adopt! [_ kid alg material]
        ;; derived material under this provider is already a nacljc secret
        (swap! secrets assoc kid {:alg alg :secret material})
        nil)
      (-has? [_ kid] (contains? @secrets kid))
      (-kids [_] (set (keys @secrets)))
      (-alg [_ kid] (:alg (get @secrets kid)))
      (-with-material [_ kid f] (f (:secret (get @secrets kid))))
      (-export [_ kid] (na/secret-export (:secret (get @secrets kid)) ack))
      (-destroy! [_ kid]
        (let [[old _] (swap-vals! secrets dissoc kid)]
          (when-let [s (get-in old [kid :secret])]
            (na/secret-destroy! s)
            true))))))
