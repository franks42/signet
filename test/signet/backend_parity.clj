(ns signet.backend-parity
  "Loads BOTH backends in one process and checks they return byte-identical
   results for the same inputs (random inputs, so every run covers new
   values). JVM only: the JCA oracle cannot derive keys from seeds on bb
   (its proxy [SecureRandom] trick). Needs the :sodium alias. Not a *-test
   namespace, so the default runner skips it.

   Usage: -m signet.backend-parity [expected-backend]
   With expected-backend (jca|sodium), also checks signet.impl selected it."
  (:require [signet.impl :as impl]
            [signet.impl.jvm :as jca]
            [signet.impl.sodium :as na]))

(def ^:private results (atom []))

(defn- check [label ok]
  (swap! results conj [label ok])
  (println (if ok "  ok  " "  FAIL") label))

(defn- same? [a b] (java.util.Arrays/equals ^bytes a ^bytes b))

(defn- parity-checks
  "One round of JCA-vs-libsodium comparisons on fresh random inputs."
  []
  (let [[pub seed] (jca/generate-ed25519-keypair)
        msg        (jca/random-bytes 100)
        [xpub xpriv] (jca/generate-x25519-keypair)
        key        (jca/random-bytes 32)
        nonce      (jca/random-bytes 12)
        aad        (jca/random-bytes 7)]
    (check "ed25519-seed->public-key" (same? (jca/ed25519-seed->public-key seed) (na/ed25519-seed->public-key seed)))
    (check "ed25519-seed->public-key matches JCA keygen" (same? pub (na/ed25519-seed->public-key seed)))
    (check "ed25519-sign" (same? (jca/ed25519-sign seed msg) (na/ed25519-sign seed msg)))
    (check "ed25519-verify (cross)" (and (jca/ed25519-verify pub msg (na/ed25519-sign seed msg))
                                         (na/ed25519-verify pub msg (jca/ed25519-sign seed msg))))
    (check "ed25519-verify rejects tampering, both" (and (not (jca/ed25519-verify pub (jca/random-bytes 100) (jca/ed25519-sign seed msg)))
                                                         (not (na/ed25519-verify pub (jca/random-bytes 100) (na/ed25519-sign seed msg)))))
    (check "ed25519-verify false on short signature, both" (and (false? (jca/ed25519-verify pub msg (byte-array 10)))
                                                                (false? (na/ed25519-verify pub msg (byte-array 10)))))
    (check "sha-256" (same? (jca/sha-256 msg) (na/sha-256 msg)))
    (check "x25519-private->public-key" (same? (jca/x25519-private->public-key xpriv) (na/x25519-private->public-key xpriv)))
    (check "x25519-private->public-key matches JCA keygen" (same? xpub (na/x25519-private->public-key xpriv)))
    (check "ed25519-pub->x25519-pub" (same? (jca/ed25519-pub->x25519-pub pub) (na/ed25519-pub->x25519-pub pub)))
    (check "ed25519-seed->x25519-private" (same? (jca/ed25519-seed->x25519-private seed) (na/ed25519-seed->x25519-private seed)))
    (check "x25519-dh" (same? (jca/x25519-dh xpriv (jca/ed25519-pub->x25519-pub pub))
                              (na/x25519-dh xpriv (na/ed25519-pub->x25519-pub pub))))
    (check "hmac-sha-256 (key length 13)" (let [k (jca/random-bytes 13)] (same? (jca/hmac-sha-256 k msg) (na/hmac-sha-256 k msg))))
    (check "hkdf-sha-256 (2-arity)" (same? (jca/hkdf-sha-256 key 42) (na/hkdf-sha-256 key 42)))
    (let [salt (jca/random-bytes 16)
          info (.getBytes "signet/box/v1" "UTF-8")]
      (check "hkdf-sha-256 (salt, info)" (same? (jca/hkdf-sha-256 key salt info 32)
                                                (na/hkdf-sha-256 key salt info 32))))
    (check "chacha20-poly1305-encrypt" (same? (jca/chacha20-poly1305-encrypt key nonce msg aad)
                                              (na/chacha20-poly1305-encrypt key nonce msg aad)))
    (check "chacha20-poly1305-encrypt, nil aad" (same? (jca/chacha20-poly1305-encrypt key nonce msg nil)
                                                       (na/chacha20-poly1305-encrypt key nonce msg nil)))
    (check "chacha20-poly1305 cross decrypt" (and (same? msg (na/chacha20-poly1305-decrypt key nonce (jca/chacha20-poly1305-encrypt key nonce msg aad) aad))
                                                  (same? msg (jca/chacha20-poly1305-decrypt key nonce (na/chacha20-poly1305-encrypt key nonce msg aad) aad))))))

(defn -main [& [expected]]
  (println "runtime:" (or (some->> (System/getProperty "babashka.version") (str "babashka "))
                          (str "JVM " (System/getProperty "java.version")))
           "| selected backend:" impl/backend)
  (when (and expected (not= (keyword expected) impl/backend))
    (println "WRONG BACKEND: expected" expected)
    (System/exit 2))
  (dotimes [_ 3] (parity-checks))
  (let [fails (remove second @results)]
    (println (format "%d checks, %d failed" (count @results) (count fails)))
    (System/exit (if (seq fails) 1 0))))
