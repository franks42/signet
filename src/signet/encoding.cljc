(ns signet.encoding
  "Encoding utilities: base64url (canonical for key identifiers) and hex
   (for interop with external tools that expect the traditional format)."
  #?(:clj (:import [java.util Base64])))

(defn bytes->base64url
  "Encode byte array to base64url string (no padding)."
  [^bytes bs]
  #?(:clj  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs)
     :cljs (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defn base64url->bytes
  "Decode base64url string (with or without padding) to byte array."
  [^String s]
  #?(:clj  (.decode (Base64/getUrlDecoder) s)
     :cljs (throw (js/Error. "Not yet implemented for ClojureScript"))))

(defn bytes->hex
  "Encode byte array to lowercase hex string."
  [^bytes bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn hex->bytes
  "Decode a hex string (upper or lower case) to a byte array.
   Accepts an optional 0x prefix."
  [^String s]
  (let [s (if (and (>= (count s) 2)
                   (= "0x" (subs s 0 2)))
            (subs s 2)
            s)]
    (when (odd? (count s))
      (throw (ex-info "hex string must have even length" {:length (count s)})))
    (byte-array (map (fn [[a b]]
                       (unchecked-byte (Integer/parseInt (str a b) 16)))
                     (partition 2 s)))))
