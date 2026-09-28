(ns signet.concurrency-test
  "Destroying a key while another thread uses it (docs/11, part 1). Under
   the :sodium provider an operation gets the nacljc secret itself, and
   nacljc refuses to free a secret in use (::secret-in-use). The vault
   must neither forget such a secret without freeing it, nor fail: a
   destroy waits for the operations in flight."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.vault :as vault]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (vault/reset-default-vault!) (f)))

(def ^:private sodium? (= :sodium impl/backend))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(defn- in-flight
  "Start an operation on h on another thread that holds the material
   until release is delivered. Returns [op-future material-promise]."
  [h release]
  (let [seen (promise)
        op   (future (vault/with-material h (fn [m] (deliver seen m) @release :done)))]
    [op seen]))

(defn- secret-destroyed? [s]
  (@(requiring-resolve 'nacljc.core/secret-destroyed?) s))

(deftest destroy-waits-for-operations-in-flight
  (when sodium?
    (let [h        (vault/generate-signing-key!)
          release  (promise)
          [op m]   (in-flight h release)
          material (deref m 5000 nil)
          d        (future (error-type #(vault/destroy! h)))]
      (is (some? material) "the operation is running")
      (is (= :timeout (deref d 200 :timeout)) "destroy! waits while the key is in use")
      (deliver release true)
      (is (= :done (deref op 5000 :timeout)))
      (is (= :no-throw (deref d 5000 :timeout)) "then destroys it")
      (is (secret-destroyed? material) "the secret is freed, not just forgotten")
      (is (nil? (vault/handle (:kid h)))))))

(deftest unregister-waits-too
  (when sodium?
    (vault/register-vault! :c)
    (let [h        (vault/generate-encryption-key! :c)
          release  (promise)
          [op m]   (in-flight h release)
          material (deref m 5000 nil)
          d        (future (error-type #(vault/unregister-vault! :c)))]
      (is (= :timeout (deref d 200 :timeout)))
      (deliver release true)
      (is (= :done (deref op 5000 :timeout)))
      (is (= :no-throw (deref d 5000 :timeout)))
      (is (secret-destroyed? material)))))

(deftest destroying-from-inside-an-operation-is-refused
  ;; waiting would deadlock: the operation waits for itself
  (let [h (vault/generate-signing-key!)
        r (future (error-type #(vault/with-material h (fn [_] (vault/destroy! h)))))]
    (is (= :signet.vault/destroy-inside-operation (deref r 5000 :timeout)))
    (is (some? (vault/handle (:kid h))) "nothing was destroyed")))

(deftest operations-run-in-parallel
  (testing "two operations on the same vault do not wait for each other"
    (let [a       (vault/generate-signing-key!)
          b       (vault/generate-signing-key!)
          release (promise)
          [op1 m] (in-flight a release)]
      (deref m 5000 nil)
      (is (= 64 (count (deref (future (vault/sign b (byte-array 1))) 5000 nil))))
      (deliver release true)
      (is (= :done (deref op1 5000 :timeout))))))

(deftest the-sodium-provider-keeps-a-secret-it-cannot-free
  ;; nacljc refuses to free a secret while a call reads it; the provider
  ;; must then keep the entry (to destroy later), not forget it
  (when sodium?
    (let [p      (vault/default-provider)
          kid    (key/kid (vault/-generate! p :ed25519))
          s      (vault/-with-material p kid identity)
          open!  @(requiring-resolve 'nacljc.core/open-secret!)
          close! @(requiring-resolve 'nacljc.core/close-secret!)]
      (open! s)
      (try
        (is (= :nacljc.core/secret-in-use (error-type #(vault/-destroy! p kid))))
        (is (vault/-has? p kid) "still held, so it can be destroyed later")
        (finally (close! s)))
      (vault/-destroy! p kid)
      (is (secret-destroyed? s))
      (is (not (vault/-has? p kid))))))
