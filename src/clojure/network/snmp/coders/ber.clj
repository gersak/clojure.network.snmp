(ns clojure.network.snmp.coders.ber
  (require [clojure.zip :as zip]
           [clojure.math.numeric-tower :refer (abs expt)])
  (:import [java.io OutputStream FileOutputStream]
           [java.nio.channels Channels]
           [java.math BigInteger]
           [java.nio
            ByteBuffer
            Buffer
            ByteOrder]))

;; Function handles BER encoding rules:
;; 1* The first octet has value 40 * value1 + value2.
;;    (This is unambiguous, since value1 is limited to values 0, 1, and 2;
;;    value2 is limited to the range 0 to 39 when value1 is 0 or 1;
;;    and, according to X.208, n is always at least 2.)
;; 2* The following octets, if any, encode value3, ..., valuen.
;;    Each value is encoded base 128, most significant digit first,
;;    with as few digits as possible, and the most significant bit
;;    of each octet except the last in the value's encoding set to \"1.\"

(defn sbyte [v]
  (if (neg? v)
    (if (< v -128) (+ v 256) v)
    (if (> v 127) (- v 256) v)))

(defn ubyte [v]
  (if (neg? v) (+ 256 v) v))


(defn int2ber [x]
  (do
    (assert (number? x))
    (.toByteArray (BigInteger. (str x)))))

(defn ber2int [#^bytes x]
  (BigInteger. x))

(defn str2ber [^String x]
  (.getBytes x))

;; Characters that are not supposed to be used in String.
;; Based on this character HEX encoding is detected
(def control-characters (set (flatten [(range 0 7) (range 16 28)])))

(defn ber2str [#^bytes x]
  (letfn [(hex-fn [y] (clojure.string/upper-case
                        (apply str
                               (map #(if-not (> (count %) 1) (str "0" %) %) (map #(Integer/toHexString %) (map ubyte (seq y)))))))]
    (if (some #(contains? control-characters %) (seq x))
      (hex-fn x)
      (let [current-value (String. x)
            real-value (apply str (map char (map ubyte (seq x))))]
        (if (= current-value real-value) current-value (hex-fn x))))))


(defn- length2ber [v]
  (assert (pos? v))
  (let [x (int2ber v)
        hf (fn [y] (.array (doto
                     (ByteBuffer/allocate (inc (count y)))
                     (.put (-> (count y) (bit-or 0x80) sbyte byte))
                     (.put y))))]
    (cond
      (and (> (abs v) 127) (< (abs v) 256)) (byte-array (rest x))
      (> (abs v) 255) (hf x)
      :else x)))

(defn- ber2length [v]
  (let [x (seq v)]
    (if (bit-test (first x) 7)
      (do
        (assert (> (count x) 1))
        (BigInteger. 1 (byte-array (take (bit-and 0x7f (first x)) (rest x)))))
      (first x))))

;; BER OID encoder and decoder functions
;; Function normalizes value to BER OID encoding rules
(defn ber-oid-normalize [v]
  (if (< v 127) (byte v)
    (loop [x [(mod v 128)]
           r (int (/ v 128))]
      (if (> r 127) (recur (conj x (bit-or 0x80 (mod r 128))) (int (/ r 128)))
        (reverse (conj x (bit-or 0x80 (mod r 128))))))))

(defn ber-oid-encode [v]
  (if (zero? (first v)) (seq [0])
    (let [fv (+ (* 40 (first v)) (second v))
          rv (map ber-oid-normalize (drop 2 v))
          nv (vec (map sbyte (flatten [fv rv])))]
      (byte-array (map byte (seq nv))))))

;; BER-OID decoding function
;; For more information see http://luca.ntop.org/Teaching/Appunti/asn1.html

(defn ber-oid-decode [#^bytes v]
  (let [oid-temp (map ubyte (seq v))
        fpart [(int (/ (first oid-temp) 40)) (rem (first oid-temp) 40)]
        rpart (loop [col (next oid-temp)
                     f (if (> (first oid-temp) 128) true false)
                     r []
                     t (if f [(first oid-temp)] [])]
                (if (nil? (first col)) r
                  (if (< (first col) 128)
                    (if f
                      (recur (rest col) false (conj r (conj t (first col))) [])
                      (recur (rest col) false (conj r (first col)) []))
                    (recur (rest col) true r (conj t (first col))))))
        hf (fn [x] (if (coll? x)
                     (let [a (reverse (map #(bit-and 0x7f %) x))
                           exponents (map #(expt 128 %) (range 0 (count a)))
                           pairs (partition 2 (interleave a exponents))]
                       (reduce + (map #(apply * %) pairs)))
                     x))]
    (doall (if (zero? (first fpart)) [0] (vec (map hf (into fpart rpart)))))))
