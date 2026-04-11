(ns build
  "Build script for signet.

   Usage:
     clojure -T:build jar      ; Create JAR
     clojure -T:build install  ; Install to local Maven repo (~/.m2/repository)
     clojure -T:build deploy   ; Build JAR and deploy to Clojars (requires creds)
     clojure -T:build clean    ; Clean build artifacts"
  (:require [clojure.tools.build.api :as b]))

(def lib 'com.github.franks42/signet)
(def version "0.3.1")
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
(def basis (delay (b/create-basis {:project "deps.edn" :root nil})))

(defn clean [_]
  (println "Cleaning target directory...")
  (b/delete {:path "target"})
  (println "Done."))

(defn jar [_]
  (clean nil)
  (println (format "Building %s version %s..." lib version))
  (println (format "JAR file: %s" jar-file))

  (b/copy-dir {:src-dirs   ["src"]
               :target-dir class-dir})

  (b/write-pom
   {:class-dir class-dir
    :lib       lib
    :version   version
    :basis     @basis
    :src-dirs  ["src"]
    :pom-data  [[:description "Ed25519/X25519 crypto primitives, capability chains, and SSH key import for Clojure"]
                [:url "https://github.com/franks42/signet"]
                [:licenses
                 [:license
                  [:name "EPL-2.0"]
                  [:url "https://www.eclipse.org/legal/epl-2.0/"]]]
                [:scm
                 [:url "https://github.com/franks42/signet"]
                 [:connection "scm:git:https://github.com/franks42/signet.git"]
                 [:developerConnection "scm:git:ssh://git@github.com/franks42/signet.git"]
                 [:tag (str "v" version)]]]})

  (b/jar {:class-dir class-dir :jar-file jar-file})
  (println (format "Created: %s" jar-file)))

(defn install [_]
  (jar nil)
  (println (format "Installing %s to local Maven repository..." lib))
  (b/install {:basis     @basis
              :lib       lib
              :version   version
              :jar-file  jar-file
              :class-dir class-dir})
  (println (format "Installed %s/%s to ~/.m2/repository" lib version))
  (println)
  (println "To use in deps.edn:")
  (println (format "  %s {:mvn/version \"%s\"}" lib version)))
