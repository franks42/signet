(ns signet.suite
  "Runs signet's test namespaces in-process and checks which crypto backend
   signet.impl selected. For babashka, which has no cognitect test-runner;
   on the JVM, clojure -M:test[:sodium] runs the same tests. Not a *-test
   namespace, so the default runner skips it.

   Usage: -m signet.suite <expected-backend>   (jca | sodium)
   Exits 1 on failures, 2 if the wrong backend was selected."
  (:require [clojure.test :as t]
            [signet.impl :as impl]))

(def ^:private test-nss
  '[signet.key-test signet.sign-test signet.chain-test signet.encryption-test
    signet.session-test signet.ssh-test signet.bb-smoke-test signet.trust-test])

(defn -main [& [expected]]
  (let [bb? (System/getProperty "babashka.version")
        ;; BouncyCastle (secp256k1) cannot load on bb
        nss (cond-> test-nss (not bb?) (conj 'signet.secp256k1-test))]
    (println "runtime:" (if bb? (str "babashka " bb?) (str "JVM " (System/getProperty "java.version")))
             "| backend:" impl/backend)
    (when (and expected (not= (keyword expected) impl/backend))
      (println "WRONG BACKEND: expected" expected)
      (System/exit 2))
    (apply require nss)
    (let [{:keys [fail error]} (apply t/run-tests nss)]
      (System/exit (if (pos? (+ fail error)) 1 0)))))
