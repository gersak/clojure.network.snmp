(ns clojure.network.snmp.utils)


(defn numeric?
  "https://rosettacode.org/wiki/Determine_if_a_string_is_numeric#Clojure"
  [s]
  (cond (number? s) true
        (string? s) (if-not (= s "-")
                      (if-let [s (seq s)]
                        (let [s (if (= (first s) \-) (next s) s)
                              s (drop-while #(Character/isDigit %) s)
                              s (if (= (first s) \.) (next s) s)
                              s (drop-while #(Character/isDigit %) s)]
                          (empty? s))))
        :else false))

(defn parse-number [value num-type]
  (cond (numeric? value) (num-type (bigdec value))
        (boolean? value) (num-type (get {false 0 true 1} value))))

(defn parse-int [value]
  (parse-number value int))
