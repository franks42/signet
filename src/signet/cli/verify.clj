(ns signet.cli.verify
  "CLI entry point for verifying ECDSA / Ed25519 signatures.

   Usage:
     clojure -M -m signet.cli.verify [--curve secp256k1|ed25519]
                                     --pubkey  <hex>
                                     --message <hex|@file>
                                     --signature <hex|@file>

   Default curve: ed25519. Hex inputs are interpreted as raw bytes.
   '@<path>' inputs read raw bytes from a file. Exit code 0 = valid;
   exit code 1 = invalid; exit code 2 = bad arguments.

   Designed to be invoked from bb's `verify` task — bb itself can't
   load BouncyCastle, so secp256k1 verification shells out to JVM
   Clojure via this entry point."
  (:require [signet.encoding :as enc]
            [signet.key :as key]
            [signet.sign :as sign])
  (:gen-class))

(defn- read-bytes
  "If `s` starts with '@', read raw bytes from the named file; else
   interpret `s` as a hex string."
  [s]
  (if (and s (.startsWith ^String s "@"))
    (let [path (subs s 1)
          f    (java.io.File. path)]
      (when-not (.exists f)
        (throw (ex-info (str "file not found: " path) {:path path})))
      (let [out (byte-array (.length f))]
        (with-open [in (java.io.FileInputStream. f)]
          (.readNBytes in out 0 (alength out)))
        out))
    (enc/hex->bytes s)))

(defn- parse-args [args]
  (loop [acc {} [k v & more] args]
    (cond
      (nil? k) acc
      (and (string? k) (.startsWith ^String k "--"))
      (recur (assoc acc (keyword (subs k 2)) v) more)
      :else (throw (ex-info (str "unexpected arg: " k) {:arg k})))))

(defn- die [code msg]
  (binding [*out* *err*]
    (println msg))
  (System/exit code))

(defn -main [& args]
  (let [opts (try (parse-args args)
                  (catch Exception e (die 2 (str "argument error: " (ex-message e)))))
        curve (keyword (or (:curve opts) "ed25519"))
        _    (when-not (#{:ed25519 :secp256k1 :Ed25519} curve)
               (die 2 (str "unsupported --curve: " (:curve opts) " (use ed25519 or secp256k1)")))
        crv-tag (case curve
                  :ed25519   :Ed25519
                  :Ed25519   :Ed25519
                  :secp256k1 :secp256k1)
        pubkey-hex (or (:pubkey opts)
                       (die 2 "missing --pubkey <hex>"))
        msg-input  (or (:message opts)
                       (die 2 "missing --message <hex|@file>"))
        sig-input  (or (:signature opts)
                       (die 2 "missing --signature <hex|@file>"))
        pub-bytes (try (enc/hex->bytes pubkey-hex)
                       (catch Exception e (die 2 (str "bad --pubkey: " (ex-message e)))))
        msg-bytes (try (read-bytes msg-input)
                       (catch Exception e (die 2 (str "bad --message: " (ex-message e)))))
        sig-bytes (try (read-bytes sig-input)
                       (catch Exception e (die 2 (str "bad --signature: " (ex-message e)))))
        pub        (case crv-tag
                     :Ed25519
                     (key/->Ed25519PublicKey :signet/ed25519-public-key :Ed25519 pub-bytes)

                     :secp256k1
                     (key/->Secp256k1PublicKey :signet/secp256k1-public-key :secp256k1 pub-bytes))
        result (try (sign/verify pub msg-bytes sig-bytes)
                    (catch Exception e
                      (binding [*out* *err*]
                        (println (str "verify error: " (ex-message e))))
                      false))]
    (if result
      (do (println "VALID") (System/exit 0))
      (do (println "INVALID") (System/exit 1)))))
