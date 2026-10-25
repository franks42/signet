(ns signet.tutorial-test
  "Runs the tutorial (docs/tutorial/*.md) as a test, so it cannot drift
   from the code. In each chapter, every ```clojure block whose first line
   contains [works] is evaluated, in order, in one namespace per chapter.
   A line `;; => <edn>` checks the value of the code above it (since the
   previous check): equal, or for a map, every expected key equal (the
   actual map may have more). [change] and [new] blocks show the API we
   want and are not run.

   Skipped (with a note) when docs/tutorial is absent, as in the
   consumer check, which copies tests only."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [signet.key :as key]
            [signet.vault :as vault]))

(def ^:private dir (io/file "docs/tutorial"))

(defn- chapters []
  (->> (.listFiles dir)
       (filter #(re-matches #"\d\d-.*\.md" (.getName ^java.io.File %)))
       (sort-by #(.getName ^java.io.File %))))

(defn- blocks
  "The text of each ```clojure block in md whose first line has [works]."
  [md]
  (->> (re-seq #"(?s)```clojure\n(.*?)```" md)
       (map second)
       (filter #(str/includes? (first (str/split-lines %)) "[works]"))))

(defn- steps
  "block split at its `;; =>` lines: [[code expected-or-nil] …]."
  [block]
  (loop [lines (str/split-lines block) code [] out []]
    (if-let [[l & more] (seq lines)]
      (if-let [[_ e] (re-matches #"\s*;; => (.*)" l)]
        (recur more [] (conj out [(str/join "\n" code) (edn/read-string e)]))
        (recur more (conj code l) out))
      (cond-> out (seq code) (conj [(str/join "\n" code) nil])))))

(defn- matches? [expected actual]
  (if (map? expected)
    (and (map? actual) (every? (fn [[k v]] (= v (get actual k))) expected))
    (= expected actual)))

(defn- fresh! []
  (key/clear-key-store!)
  (vault/reset-default-vault!)
  (doseq [id (vault/vault-ids) :when (not= :default id)] (vault/unregister-vault! id)))

(deftest the-tutorial-runs
  (if-not (.isDirectory dir)
    (println "signet.tutorial-test: docs/tutorial not found, skipped")
    (doseq [f (chapters)]
      (testing (.getName ^java.io.File f)
        (fresh!)
        (let [ns-sym (gensym "tutorial-")
              bs (blocks (slurp f))]
          (is (seq bs) "the chapter has [works] blocks")
          (try
            (binding [*ns* (create-ns ns-sym)]
              (refer-clojure)
              (doseq [b bs [code expected] (steps b)]
                (let [v (load-string code)]
                  (when (some? expected)
                    (is (matches? expected v) (str "\n" (str/trim code) "\n;; => " (pr-str v)))))))
            (finally (remove-ns ns-sym) (fresh!))))))))
