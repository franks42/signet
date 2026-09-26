(ns signet.consumer-check
  "Run signet's own tests against a packaged signet jar, from a scratch
   project that has only the tests (no src/): JVM jca, JVM sodium with the
   backend-parity check, and bb sodium.

     bb test:jar            ; the locally installed jar (build.clj's version)
     bb test:clojars 0.7.0  ; a release, fetched from Clojars into an empty
                            ; local Maven repository

   Asserts that signet really loaded from a jar."
  (:require [babashka.fs :as fs]
            [babashka.process :as p]
            [clojure.string :as str]))

(def nacljc "com.github.franks42/nacljc {:mvn/version \"0.3.0\"}")

(defn- build-version []
  (or (second (re-find #"\(def version \"([^\"]+)\"\)" (slurp "build.clj")))
      (throw (ex-info "cannot parse the version from build.clj" {}))))

(defn- sh [opts & args]
  (println "  $" (str/join " " (map #(if (> (count %) 90) (str (subs % 0 87) "...") %) args)))
  (let [{:keys [exit out err]} @(p/process args (merge {:out :string :err :string} opts))]
    (print out) (flush)
    (when-not (zero? exit)
      (binding [*out* *err*] (println err))
      (throw (ex-info (str "failed: " (first args)) {:exit exit})))
    out))

(defn check [version fresh-repo?]
  (let [tests (str (fs/absolutize "test"))
        dir   (str (fs/create-temp-dir {:prefix "signet-consumer-"}))
        repo  (when fresh-repo? (str (fs/create-dirs (fs/path dir "m2"))))
        coord (str "com.github.franks42/signet {:mvn/version \"" version "\"}")
        local (when repo (str " :mvn/local-repo \"" repo "\""))]
    (spit (str (fs/path dir "deps.edn"))
          (str "{:paths [\"" tests "\"] :deps {" coord "}" local
               " :aliases {:sodium {:extra-deps {" nacljc "}"
               " :jvm-opts [\"--enable-native-access=ALL-UNNAMED\" \"-Dsignet.backend=sodium\"]}}}"))
    (try
      (let [where (sh {:dir dir} "clojure" "-M" "-e"
                      "(println :signet-from (str (clojure.java.io/resource \"signet/key.cljc\")))")]
        (when-not (re-find #":signet-from jar:file:" where)
          (throw (ex-info "signet did not load from a jar" {:out where})))
        (when (and repo (not (str/includes? where repo)))
          (throw (ex-info "signet did not come from the fresh local repository" {:out where})))
        (println "signet" version "loads from the jar"))
      (sh {:dir dir} "clojure" "-M" "-m" "signet.suite" "jca")
      (sh {:dir dir} "clojure" "-M:sodium" "-m" "signet.suite" "sodium")
      (sh {:dir dir} "clojure" "-M:sodium" "-m" "signet.backend-parity" "sodium")
      (sh {:dir dir :extra-env {"SIGNET_BACKEND" "sodium"}}
          "bb" "-e" (str "(babashka.deps/add-deps '{:deps {" coord " " nacljc "}" local "})"
                         "(babashka.classpath/add-classpath \"" tests "\")"
                         "(require 'signet.suite) (signet.suite/-main \"sodium\")"))
      (println (str "\nsignet " version ": the suite passes from the jar (JVM jca, JVM sodium + parity, bb sodium)"))
      (finally (fs/delete-tree dir)))))

(defn -main [& [mode version]]
  (case mode
    "local"   (check (or version (build-version)) false)
    "clojars" (check (or version (throw (ex-info "usage: clojars <version>" {}))) true)))
