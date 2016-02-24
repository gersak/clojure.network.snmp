(ns clojure.network.snmp.coders.snmp
  (:import [java.io OutputStream FileOutputStream]
           [java.nio.channels Channels]
           [java.nio ByteBuffer Buffer ByteOrder]
           [ber BERUnit]
           [java.util Date])
  (:require
    [clojure.network.snmp.coders.ber :refer :all]
    [clojure.network.snmp.protocol :refer [snmp-encode
                                           snmp-decode]]
    [clojure.set :refer (difference map-invert)]))


(def snmp-pdu-type
  {:get-request -96
   :get-next-request -95
   :response -94
   :set-request -93
   :get-bulk-request -91
   :inform-request -90
   :trap -89
   :report -88
   :sequence 48})


(def snmp-variables
  {:IpAddress 0x40
   :Counter32 0x41
   :Gauge32 0x42
   :Timeticks 0x43
   :Opaque 0x44
   :NsapAddress 0x45
   :Counter64 0x46
   :Uinteger32 0x47
   :Integer 0x02
   :Null 0x05
   :OID 0x06
   :OctetString 0x04
   :noSuchInstance -127})

(def snmp-headers (conj snmp-variables snmp-pdu-type))

(def ber-hi-limit (reduce * (repeat 32 2)))

;; Here are defined functions that encode SNMP values to their byte value
(def snmp-encodings
  {:Integer (fn [^Integer x] (int2ber x))
   :Null (fn [_] (byte-array (map byte [5 0])))
   :OctetString (fn [^String x] (str2ber x))
   :OID (fn [x] (ber-oid-encode x))
   :IpAddress (fn [x] (byte-array (map byte (map sbyte x))))
   :Counter32 (fn [x] (int2ber (min x ber-hi-limit)))
   :Timeticks (fn [x] (int2ber (min x ber-hi-limit)))
   :Gauge32 (fn [x] (int2ber (min x ber-hi-limit)))
   :noSuchInstance (fn [_] (byte-array (map byte [-127 0])))
   :sequence snmp-encode
   :get-request snmp-encode
   :get-next-request snmp-encode
   :response snmp-encode
   :get-bulk-request snmp-encode
   :trap snmp-encode
   :reports snmp-encode
   :set-request snmp-encode
   :inform-request snmp-encode})

;; Here are defined functions that decode byte values to their SNMP values
(def snmp-decodings
  {:Integer (fn [x] (ber2int x))
   :Null (fn [_] nil)
   :OctetString (fn [x] (ber2str x))
   :OID (fn [x] (ber-oid-decode x))
   :IpAddress (fn [x] (vec (map ubyte x)))
   :Counter32 (fn [x] (rem (ber2int x) ber-hi-limit))
   :Timeticks (fn [x] (ber2int x))
   :Gauge32 (fn [x] (ber2int x))
   :noSuchInstance (fn [_] nil)
   :sequence 'snmp-decode
   :get-request 'snmp-decode
   :set-request 'snmp-decode
   :response 'snmp-decode
   :get-next-request 'snmp-decode
   :get-bulk-request 'snmp-decode
   :trap 'snmp-decode
   :report 'snmp-decode
   :inform-request 'snmp-decode})

(def BERCoder
  (reify clojure.network.snmp.protocol.SNMPCoderProtocol
    (snmp-encode [this v]
      (let [t (:type v)]
        (if (bit-test (t snmp-headers) 5)
          (.bytes (BERUnit. (t snmp-headers) (byte-array (reduce concat (for [x (:value v)] (snmp-encode this x))))))
          (if (and (not= :Null t) (not= :noSuchInstance t))
            (.bytes (BERUnit. (t snmp-headers) ((t snmp-encodings) (:value v))))
            ((t snmp-encodings) (:value v))))))
    (snmp-decode [this v]
      (let [u (BERUnit. v)
            original-type (get (map-invert snmp-headers) (.header u))]
        (if (bit-test (.header u) 5)
          ;; Check if it is a construct
          (loop [s (.value u)
                 values []]
            ;; If true loop for each value in this construct
            (if (empty? s) {:type original-type :value values}
              ;; Make new unit
              (let [u (BERUnit. s)]
                ;; Get unit type
                (when-let [t (get (map-invert snmp-headers) (.header u))]
                  ;; Separate unit value from rest of the sequences of cunstruct
                  (let [[v1 r1] [(.value u) (drop (count (.bytes u)) s)]]
                    ;; Test if unit itself is construct
                    (if (bit-test (.header u) 5)
                      ;; If it is then snmp-decode itself recursive and return rest of seq to
                      ;; resolution
                      (recur (byte-array r1) (conj values (snmp-decode this s)))
                      ;; If not then return concrete value and move forward with resolution
                      (recur (byte-array r1) (conj values {:type t :value ((t snmp-decodings) v1)}))))))))
          (let [nv {:type original-type :value ((original-type snmp-decodings) v)}]
            {:type original-type :value nv}))))))
