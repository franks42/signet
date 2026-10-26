#!/usr/bin/env bb
(ns mdfmt
  "Format markdown to editmd's serializer style.

  Usage: bb scripts/mdfmt.clj [--write] FILE...
  (or `bb md` / `bb md:fix`, which default to every tracked .md)

  Without --write, lists the files that would change and exits 1 if any
  would. With --write, rewrites them in place.

  Formatting only, never inside fenced code or inline code spans:
  - bullet markers `*` and `+` become `-`;
  - `*italic*` becomes `_italic_` (single asterisks only, also across the
    lines of one paragraph and inside table cells);
  - ordered lists increment from the list's first number, which is kept
    (a list may start at 0);
  - tables are padded so the pipes line up (separator dashes to the
    column width, alignment colons kept, a table's indentation kept);
  - thematic breaks (`***`, `___`) become `---`.

  Line count and line wrapping never change, and a second run changes
  nothing."
  (:require [clojure.string :as str]))

(def ^:private fence #"^(\s*)(```|~~~)")
(def ^:private bullet #"^(\s*)[*+]\s+")
(def ^:private ordered #"^(\s*)(\d+)[.)]\s+")
(def ^:private hr #"^\s{0,3}((\*\s*){3,}|(_\s*){3,})$")
(def ^:private sep-cell #"^:?-+:?$")
;; A single-asterisk span, not part of ** and not inside a word.
(def ^:private italic #"(?U)(?<![\*\w\\])\*(?![\s\*])([^*]+?)(?<![\s\\])\*(?![\*\w])")
(def ^:private code-span #"(`+)[^`]*?\1")

(def ^:private wide-ranges
  "Code points displayed two columns wide: CJK, fullwidth forms and the
  emoji that Unicode's East Asian Width table marks W."
  [[0x1100 0x115F] [0x231A 0x231B] [0x23E9 0x23EC] [0x23F0 0x23F0]
   [0x23F3 0x23F3] [0x25FD 0x25FE] [0x2614 0x2615] [0x2648 0x2653]
   [0x267F 0x267F] [0x2693 0x2693] [0x26A1 0x26A1] [0x26AA 0x26AB]
   [0x26BD 0x26BE] [0x26C4 0x26C5] [0x26CE 0x26CE] [0x26D4 0x26D4]
   [0x26EA 0x26EA] [0x26F2 0x26F3] [0x26F5 0x26F5] [0x26FA 0x26FA]
   [0x26FD 0x26FD] [0x2705 0x2705] [0x270A 0x270B] [0x2728 0x2728]
   [0x274C 0x274C] [0x274E 0x274E] [0x2753 0x2755] [0x2757 0x2757]
   [0x2795 0x2797] [0x27B0 0x27B0] [0x27BF 0x27BF] [0x2B1B 0x2B1C]
   [0x2B50 0x2B50] [0x2B55 0x2B55] [0x2E80 0x303E] [0x3041 0x33FF]
   [0x3400 0x4DBF] [0x4E00 0x9FFF] [0xA000 0xA4CF] [0xAC00 0xD7A3]
   [0xF900 0xFAFF] [0xFE30 0xFE4F] [0xFF00 0xFF60] [0xFFE0 0xFFE6]
   [0x1F300 0x1F64F] [0x1F680 0x1F6FF] [0x1F900 0x1F9FF]
   [0x20000 0x3FFFD]])

(defn- width
  "Display width: wide characters count 2, combining marks 0."
  [s]
  (reduce (fn [w cp]
            (cond
              (= (Character/getType (int cp)) Character/NON_SPACING_MARK) w
              (some (fn [[lo hi]] (<= lo cp hi)) wide-ranges) (+ w 2)
              :else (inc w)))
          0
          (iterator-seq (.iterator (.codePoints ^String s)))))

(defn- fix-italic
  "`*x*` to `_x_` in text that may span lines, code spans protected."
  [text]
  (let [spans (atom [])
        prot (str/replace text code-span
                          (fn [[m]]
                            (swap! spans conj m)
                            (str "\u0000" (dec (count @spans)) "\u0000")))
        prot (str/replace prot italic (fn [[_ x]] (str "_" x "_")))]
    (str/replace prot #"\u0000(\d+)\u0000"
                 (fn [[_ n]] (nth @spans (parse-long n))))))

(defn- split-row
  "A table row's cells; pipes inside code spans or escaped stay."
  [line]
  (let [s (str/trim line)
        s (if (str/starts-with? s "|") (subs s 1) s)
        s (if (and (str/ends-with? s "|") (not (str/ends-with? s "\\|")))
            (subs s 0 (dec (count s)))
            s)
        n (count s)]
    (loop [i 0, cur "", cells [], in-code false, ticks ""]
      (if (>= i n)
        (conj cells (str/trim cur))
        (let [ch (.charAt s i)]
          (cond
            (= ch \`)
            (let [j (loop [j i] (if (and (< j n) (= (.charAt s j) \`)) (recur (inc j)) j))
                  run (subs s i j)]
              (cond
                (not in-code) (recur j (str cur run) cells true run)
                (= run ticks) (recur j (str cur run) cells false ticks)
                :else (recur j (str cur run) cells in-code ticks)))

            (and (= ch \\) (< (inc i) n))
            (recur (+ i 2) (str cur (subs s i (+ i 2))) cells in-code ticks)

            (and (= ch \|) (not in-code))
            (recur (inc i) "" (conj cells (str/trim cur)) in-code ticks)

            :else
            (recur (inc i) (str cur ch) cells in-code ticks)))))))

(defn- table-start? [lines i]
  (and (< (inc i) (count lines))
       (str/includes? (nth lines i) "|")
       (str/starts-with? (str/trim (nth lines (inc i))) "|")
       (let [cells (split-row (nth lines (inc i)))]
         (and (>= (count cells) 2)
              (every? #(re-matches sep-cell %) (remove str/blank? cells))))))

(defn- format-table [rows]
  (let [first-row (first rows)
        indent (subs first-row 0 (- (count first-row) (count (str/triml first-row))))
        parsed (mapv #(mapv fix-italic (split-row %)) rows)
        ncol (apply max (map count parsed))
        parsed (mapv #(into % (repeat (- ncol (count %)) "")) parsed)
        widths (reduce (fn [ws [idx r]]
                         (if (= idx 1)
                           ws
                           (mapv max ws (map width r))))
                       (vec (repeat ncol 3))
                       (map-indexed vector parsed))
        pad (fn [cell w] (str cell (apply str (repeat (- w (width cell)) \space))))]
    (vec (for [[idx r] (map-indexed vector parsed)]
           (let [cells (if (= idx 1)
                         (map (fn [cell w]
                                (let [left (str/starts-with? cell ":")
                                      right (str/ends-with? cell ":")]
                                  (str (when left ":")
                                       (apply str (repeat (- w (if left 1 0) (if right 1 0)) \-))
                                       (when right ":"))))
                              r widths)
                         (map pad r widths))]
             (str indent "| " (str/join " | " cells) " |"))))))

(defn process
  "Formats a markdown string."
  [text]
  (let [lines (str/split text #"\n" -1)
        n (count lines)
        flush (fn [out para]
                (if (seq para)
                  (into out (str/split (fix-italic (str/join "\n" para)) #"\n" -1))
                  out))]
    (loop [i 0, out [], para [], in-fence false, fence-tok nil
           counters {}]                 ; indentation -> next number of the open ordered list
      (if (>= i n)
        (str/join "\n" (flush out para))
        (let [line (nth lines i)
              m (re-find fence line)]
          (cond
            (or m in-fence)
            (let [[in-fence fence-tok] (cond
                                         (not m) [in-fence fence-tok]
                                         (not in-fence) [true (nth m 2)]
                                         (= (nth m 2) fence-tok) [false fence-tok]
                                         :else [in-fence fence-tok])]
              (recur (inc i) (conj (flush out para) line) [] in-fence fence-tok counters))

            (table-start? lines i)
            (let [j (loop [j i]
                      (if (and (< j n) (str/starts-with? (str/trim (nth lines j)) "|"))
                        (recur (inc j))
                        j))]
              (recur j (into (flush out para) (format-table (subvec lines i j)))
                     [] in-fence fence-tok {}))

            (re-matches hr line)
            (recur (inc i) (conj (flush out para) "---") [] in-fence fence-tok {})

            ;; a blank line ends a paragraph but not a (loose) list
            (str/blank? line)
            (recur (inc i) (conj (flush out para) line) [] in-fence fence-tok counters)

            :else
            (let [line (str/replace-first line bullet (fn [[_ ind]] (str ind "- ")))
                  om (re-find ordered line)
                  [line counters]
                  (cond
                    om
                    (let [[whole ind num] om
                          k (count ind)
                          counters (into {} (remove (fn [[c _]] (> c k))) counters)
                          num (get counters k (parse-long num))]
                      [(str ind num ". " (subs line (count whole)))
                       (assoc counters k (inc num))])

                    ;; unindented text ends the lists
                    (and (not (Character/isWhitespace (.charAt ^String line 0)))
                         (not (str/starts-with? line "- ")))
                    [line {}]

                    :else [line counters])]
              (recur (inc i) out (conj para line) in-fence fence-tok counters))))))))

(defn -main [& args]
  (let [write? (some #{"--write"} args)
        files (remove #{"--write"} args)
        changed (doall
                 (for [f files
                       :let [src (slurp f)
                             dst (process src)]
                       :when (not= src dst)]
                   (let [n (count (filter true? (map not=
                                                     (str/split src #"\n" -1)
                                                     (str/split dst #"\n" -1))))]
                     (println (str f ": " n " lines " (if write? "formatted" "to format")))
                     (when write? (spit f dst))
                     f)))]
    (when (and (seq changed) (not write?))
      (System/exit 1))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
