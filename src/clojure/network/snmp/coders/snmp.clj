(ns clojure.network.snmp.coders.snmp
  (:import [java.io OutputStream FileOutputStream]
           [java.nio.channels Channels]
           [java.nio ByteBuffer Buffer ByteOrder]
           [ber BERUnit]
           [java.util Date])
  (:require
    [clojure.network.snmp.coders.ber :refer :all]
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

(declare snmp-construct-decode snmp-construct-encode)

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
   :sequence snmp-construct-encode
   :get-request snmp-construct-encode
   :get-next-request snmp-construct-encode
   :response snmp-construct-encode
   :get-bulk-request snmp-construct-encode
   :trap snmp-construct-encode
   :report snmp-construct-encode
   :set-request snmp-construct-encode
   :inform-request snmp-construct-encode})

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
   :sequence 'snmp-construct-decode
   :get-request 'snmp-construct-decode
   :set-request 'snmp-construct-decode
   :response 'snmp-construct-decode
   :get-next-request 'snmp-construct-decode
   :get-bulk-request 'snmp-construct-decode
   :trap 'snmp-construct-decode
   :report 'snmp-construct-decode
   :inform-request 'snmp-construct-decode})

(defn snmp-construct-decode [v]
  (loop [s v
         values []]
    (if (empty? s) values
      (let [u (BERUnit. s)]
        (when-let [t (get (map-invert snmp-headers) (.header u))]
          (let [ [v1 r1] [(.value u) (drop (count (.bytes u)) s)]]
            (if (bit-test (.header u) 5)
              (recur (byte-array r1) (conj values {:type t :value (snmp-construct-decode v1)}))
              (recur (byte-array r1) (conj values {:type t :value ((t snmp-decodings) v1)})))))))))

(defn snmp-encode [v]
  (let [t (:type v)]
    (if (bit-test (t snmp-headers) 5)
      (. (BERUnit. (t snmp-headers) (byte-array (reduce concat (for [x (:value v)] (snmp-encode x))))) bytes)
      (if (and (not= :Null t) (not= :noSuchInstance t))
        (. (BERUnit. (t snmp-headers) ((t snmp-encodings) (:value v))) bytes)
        ((t snmp-encodings) (:value v))))))

(defn snmp-construct-encode [v]
  (byte-array (reduce concat (for [x v] (snmp-encode x)))))

(defn snmp-decode [#^bytes v]
  (let [u (BERUnit. v)
        t (get (map-invert snmp-headers) (.header u))
        nv ((ns-resolve 'clojure.network.snmp.coders.snmp (symbol (get snmp-decodings t))) (.value u))]
    {:type t :value nv}))
