(ns signet.noise-vectors-test
  "Known-answer tests for signet.session against published
   Noise_KK_25519_ChaChaPoly_SHA256 vectors from two independent
   implementations:

     cacophony  github.com/haskell-cryptography/cacophony, vectors/cacophony.txt
     snow       github.com/mcginty/snow, tests/vectors/snow.txt

   Each vector fixes both static keys, both ephemerals and a prologue.
   Messages alternate initiator → responder, responder → initiator: two
   handshake messages, then transport messages. Every ciphertext must
   match byte for byte, and every payload must decrypt. This pins the wire
   format, so a refactor that changes a single byte fails here. It runs on
   every backend the suite runs on (JCA, libsodium on the JVM and on bb).

   Fixed ephemerals are injected with with-redefs on the private
   fresh-ephemeral, so production code has no injection hook."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [signet.encoding :as enc]
            [signet.impl :as impl]
            [signet.key :as key]
            [signet.session :as session]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

(def ^:private vectors
  [{:source             "cacophony"
    :prologue           "4a6f686e2047616c74"
    :init-static        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
    :init-ephemeral     "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
    :init-remote-static "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"
    :resp-static        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
    :resp-ephemeral     "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
    :resp-remote-static "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a"
    :messages
    [["4c756477696720766f6e204d69736573"
      "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440177015efc1fe7a37c629af7120a96274e6ab7afcc9261901d0e09ae32a5bb96"]
     ["4d757272617920526f746862617264"
      "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843b274d3429adc47ca093ba63ef90f8da89fda108db471dccfa4894aa7b00003"]
     ["462e20412e20486179656b"
      "966b05bc69ec01b8454d3160a214e6f24a3d884eb31ec2408af63f"]
     ["4361726c204d656e676572"
      "0ad887fba4f611bbb4afe44ba3556b8164332ca7d5934634d63d80"]
     ["4a65616e2d426170746973746520536179"
      "012b28ae646ae7830e2c5472cb023eab071c1db3d8413ec69b513b83832f974c2d"]
     ["457567656e2042f6686d20766f6e2042617765726b"
      "bb3e6a48160d9c5971d37f975727294e0d868342db31832e54d07191ab0ca3c3703b5ed3d9"]]}
   {:source             "snow"
    :prologue           "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e"
    :init-static        "9ec880ae6e9dc37277b4b7cc43a9981a2a58428648536941c787f34c840ae4b4"
    :init-ephemeral     "09469832d23dbaa396cb1e8c42c74ea73e3f88eaf39a1b9e89cc6528bd163f9a"
    :init-remote-static "673291fd3e40a0ae3008788a0e8b62a81bbabff2464bc5e76b08a9824e539c50"
    :resp-static        "2f292fe63d73808a2e5307a62428e243ba02ce8b70c949a58a4c70312fb038b5"
    :resp-ephemeral     "64fd9f17061c66df61f6e5c15ce85dbcd3aaee6e3a9f87989dc9147c6f5cb64a"
    :resp-remote-static "3198032f853c7321e63685c7331077716ed312e9fbb4822bb4dbfbcaa4590e08"
    :messages
    [["4d1f91e210b2c264713e73509808c3f6d99ca3bb115001388e630b1356a24693"
      "311304998133430ee0668c0c91cbdc445cbb3a526457b0c0b7d9dc6789be0904f7d451b7aba0f3031b46fca709b3eed813d6d1080447720cdf86bd9391c0359c717211fbcdda474c03ea5d8d03c33722"]
     ["914a3388cb8e5ef4e3d4b7ba0fc4bc0a0cbc7ff41eabdb7c9c501b4d92355fbf"
      "59028e838fa2ca7a3fc8d48b5c6379286b61507d4c91e30a0ad387164b0229060e30d119b6845417d128231555ee8666ff8beffe931b1d8296d92189472ec01cffdf25074a38a63a555bb43c749e8d05"]
     ["e3ecca19cd0e12b0607470b7b13780428e0bbe6deb02c91ecd1d5c832128258c"
      "9faaf3dc38e529089dfb9e3b830c4e014fa7204b7f52288b8f7aa6f5107e556246c2004d0236920739434810979eef50"]
     ["517c1116052039051444d2b76d00886bea074d1d730f1e3489457496cdf4d8ca"
      "007d8b6d59a12d95c335ccbd4d31486f86020b59889b8ea159b4fdaaee9334f2b9143498aeffa34219fa6c3136361b66"]]}])

(defn- hex [s] (enc/hex->bytes s))

(defn- bytes= [a b] (java.util.Arrays/equals ^bytes a ^bytes b))

(defn- fixed-ephemeral
  "A fresh-ephemeral replacement that returns the ephemeral with private
   key priv-hex."
  [priv-hex]
  (fn []
    (let [d (hex priv-hex)]
      (session/->EphemeralKeyPair :signet/ephemeral-x25519-keypair :X25519
                                  (impl/x25519-private->public-key d) d))))

(defn- write-with-ephemeral
  "write-message! with fresh-ephemeral returning the ephemeral priv-hex
   (nil: transport messages draw no ephemeral)."
  [state priv-hex payload]
  (if priv-hex
    (with-redefs [session/fresh-ephemeral (fixed-ephemeral priv-hex)]
      (session/write-message! state payload))
    (session/write-message! state payload)))

(defn- run-vector
  "Drive both sides through v's messages. Returns one entry per message:
   [index ciphertext-matches? payload-matches?]."
  [v]
  ;; The vectors give each side's static private key and the peer's static
  ;; public key; a side's own public key is its peer's remote-static.
  (let [init-kp  (key/encryption-keypair (hex (:resp-remote-static v)) (hex (:init-static v)))
        resp-kp  (key/encryption-keypair (hex (:init-remote-static v)) (hex (:resp-static v)))
        init-pub (key/public-key init-kp)
        resp-pub (key/public-key resp-kp)
        opts     {:prologue (hex (:prologue v))}]
    (loop [i 0
           init (session/initiator init-kp resp-pub opts)
           resp (session/responder resp-kp init-pub opts)
           out  []]
      (if-let [[payload-hex ct-hex] (get (:messages v) i)]
        (let [from-init? (even? i)
              eph        (case i 0 (:init-ephemeral v) 1 (:resp-ephemeral v) nil)
              [sender receiver] (if from-init? [init resp] [resp init])
              [sender' ct]      (write-with-ephemeral sender eph (hex payload-hex))
              [receiver' pt]    (session/read-message! receiver ct)
              [init' resp']     (if from-init? [sender' receiver'] [receiver' sender'])]
          (recur (inc i) init' resp'
                 (conj out [i (bytes= (hex ct-hex) ct) (bytes= (hex payload-hex) pt)])))
        {:out out :established? (and (session/established? init) (session/established? resp))}))))

(deftest published-noise-kk-vectors
  (doseq [v vectors]
    (testing (:source v)
      (let [{:keys [out established?]} (run-vector v)]
        (is (= (count (:messages v)) (count out)))
        (is established?)
        (doseq [[i ct-ok? pt-ok?] out]
          (is ct-ok? (str (:source v) " message " i ": ciphertext differs from the vector"))
          (is pt-ok? (str (:source v) " message " i ": payload did not round-trip")))))))

(deftest vectors-catch-a-changed-byte
  ;; The harness is not vacuous: a vector with one flipped ciphertext bit
  ;; must fail the comparison for that message.
  (let [v    (first vectors)
        flip (fn [h] (let [bs (hex h)]
                       (aset-byte bs 0 (unchecked-byte (bit-xor (aget bs 0) 1)))
                       (enc/bytes->hex bs)))
        v'   (update-in v [:messages 2 1] flip)
        {:keys [out]} (run-vector v')]
    (is (= [false true] (subvec (nth out 2) 1)))
    (is (every? true? (mapcat rest (concat (take 2 out) (drop 3 out)))))))
