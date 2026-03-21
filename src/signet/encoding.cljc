(ns signet.encoding
  "Encoding utilities: base64url for key identifiers."
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
