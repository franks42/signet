(ns signet.auto-lock-test
  "Auto-lock of vault files (docs/11, part 1). Most tests use a fake clock
   with long timeouts, so the real timer thread sleeps through them and
   the lazy check (on every key use) is what locks; one test uses the
   real timer with a short timeout."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.sign :as sign]
            [signet.vault :as vault]
            [signet.vault.file :as vf]))

(def ^:private sodium? (= :sodium impl/backend))

(def ^:private fast {:opslimit 1 :memlimit 8192})

(def ^:private minute 60000)

(defn- pwd ^bytes [s] (.getBytes ^String s "UTF-8"))

(defn- error-type [f]
  (try (f) :no-throw
       (catch Throwable e (or (:type (ex-data e)) [:not-ex-info (.getSimpleName (class e))]))))

(defn- drop-vaults! []
  (doseq [id (vault/vault-ids) :when (not= :default id)] (vault/unregister-vault! id))
  (vault/reset-default-vault!))

(use-fixtures :each (fn [f] (key/clear-key-store!) (drop-vaults!) (try (f) (finally (drop-vaults!)))))

(defn- tmp-path []
  (let [d (.toFile (java.nio.file.Files/createTempDirectory "signet-autolock" (make-array java.nio.file.attribute.FileAttribute 0)))]
    (.deleteOnExit d)
    (str (io/file d "vault.edn"))))

(defn- setup!
  "Vault :v with a signing key, saved to a new file with opts and a fake
   clock (an atom of ms). Returns {:clock :h :events :path}."
  [opts]
  (let [clock  (atom 0)
        events (atom [])
        path   (tmp-path)]
    (vault/register-vault! :v)
    (let [h (vault/generate-signing-key! :v)]
      (vf/create! :v path (pwd "pw")
                  (merge {:limits fast :clock #(deref clock)
                          :on-lock (fn [id reason] (swap! events conj [id reason]))}
                         opts))
      {:clock clock :h h :events events :path path})))

(defn- use! [h] (sign/sign-edn h {:x 1}))

(deftest the-decision-is-pure
  (let [due   #'signet.vault.file/lock-due
        until #'signet.vault.file/ms-until-due
        s     {:locked? false :unlocked-at 0 :last-used 100 :idle-timeout 1000 :max-unlocked 5000}]
    (is (nil? (due s 1099)))
    (is (= :idle (due s 1100)))
    (is (= :max-unlocked (due (assoc s :last-used 4900) 5000)) "the absolute limit, used or not")
    (is (nil? (due (assoc s :locked? true) 99999)))
    (is (nil? (due {:locked? false :unlocked-at 0 :last-used 0} 99999)) "no timeouts: never")
    (is (= 1000 (until s 100)))
    (is (= 0 (until s 2000)))
    (is (nil? (until {:locked? false} 0)))))

(deftest idle-timeout-locks-at-the-next-use
  (when sodium?
    (let [{:keys [clock h events]} (setup! {:idle-timeout minute})]
      (is (= minute (:locks-in (vf/status :v))))
      (reset! clock (long (* 0.9 minute)))
      (use! h)
      (reset! clock (long (* 1.8 minute)))
      (is (map? (use! h)) "each use restarts the period")
      (is (= minute (:locks-in (vf/status :v))) "a full period after the last use")
      (reset! clock (long (* 2.9 minute)))
      (is (= :signet.vault/vault-locked (error-type #(use! h))))
      (is (:locked? (vf/status :v)))
      (is (empty? (vault/handles :v)) "the keys are gone")
      (is (= [[:v :idle]] @events))
      (testing "and unlocks as usual"
        (vf/unlock! :v (pwd "pw"))
        (is (map? (use! h)))))))

(deftest writes-count-as-use
  (when sodium?
    (let [{:keys [clock h]} (setup! {:idle-timeout minute :on-dirty :discard})]
      (reset! clock (long (* 0.9 minute)))
      (vault/generate-encryption-key! :v)
      (reset! clock (long (* 1.8 minute)))
      (is (map? (use! h))))))

(deftest max-unlocked-locks-even-in-use
  (when sodium?
    (let [{:keys [clock h events]} (setup! {:max-unlocked minute})]
      (doseq [t [0.3 0.6 0.9]] (reset! clock (long (* t minute))) (use! h))
      (reset! clock minute)
      (is (= :signet.vault/vault-locked (error-type #(use! h))))
      (is (= [[:v :max-unlocked]] @events)))))

(deftest unsaved-changes-when-the-timeout-fires
  (when sodium?
    (testing ":save (default): saved, then locked"
      (let [{:keys [clock h]} (setup! {:idle-timeout minute})
            e (vault/generate-encryption-key! :v)]
        (reset! clock (* 2 minute))
        (is (= :signet.vault/vault-locked (error-type #(use! h))))
        (vf/unlock! :v (pwd "pw"))
        (is (contains? (vault/handles :v) e) "the new key was saved")))
    (drop-vaults!)
    (testing ":discard: locked, the change is lost"
      (let [{:keys [clock h]} (setup! {:idle-timeout minute :on-dirty :discard})
            e (vault/generate-encryption-key! :v)]
        (reset! clock (* 2 minute))
        (is (= :signet.vault/vault-locked (error-type #(use! h))))
        (vf/unlock! :v (pwd "pw"))
        (is (not (contains? (vault/handles :v) e)))))
    (drop-vaults!)
    (testing ":stay-unlocked: reported, and postponed for another period"
      (let [{:keys [clock h events]} (setup! {:idle-timeout minute :on-dirty :stay-unlocked})]
        (vault/generate-encryption-key! :v)
        (reset! clock (* 2 minute))
        (is (map? (use! h)) "still unlocked")
        (is (= [[:v :dirty]] @events))
        (is (= minute (:locks-in (vf/status :v))))))))

(deftest the-timer-locks-a-vault-nobody-uses
  (when sodium?
    (let [events  (atom [])
          locked  (promise)
          path    (tmp-path)
          _       (vault/register-vault! :t)
          h       (vault/generate-signing-key! :t)
          secret? @(requiring-resolve 'nacljc.core/secret-destroyed?)
          s       (vault/with-material h identity)]
      (vf/create! :t path (pwd "pw") {:limits fast :idle-timeout 300
                                      :on-lock (fn [id reason] (swap! events conj [id reason]) (deliver locked true))})
      (is (true? (deref locked 5000 false)) "locked by the timer, without any call")
      (is (:locked? (vf/status :t)))
      (is (= [[:t :idle]] @events))
      (is (secret? s) "the key's guarded memory is freed")
      (testing "after unlock! the timer runs again"
        (vf/unlock! :t (pwd "pw"))
        (is (not (:locked? (vf/status :t))))
        (is (loop [n 0]
              (cond (:locked? (vf/status :t)) true
                    (> n 100)                 false
                    :else                     (do (Thread/sleep 50) (recur (inc n))))))
        (is (= [[:t :idle] [:t :idle]] @events))))))

(deftest bad-options
  (when sodium?
    (vault/register-vault! :b)
    (doseq [opts [{:idle-timeout 0} {:max-unlocked -1} {:on-dirty :later} {:on-lock :x} {:idle-timeout 1.5}]]
      (is (= :signet.vault.file/bad-option
             (error-type #(vf/create! :b (tmp-path) (pwd "pw") (assoc opts :limits fast))))
          (pr-str opts)))))
