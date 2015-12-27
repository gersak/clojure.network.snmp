(in-ns 'kovacnica.snmp.protocol)


;; Variable bindings cast
(defn vb2str [variable-bindings & options]
  (assert (every? #(= :sequence %) (map :type variable-bindings)) "There is something wrong with input parameter. Not every variable binding is a :sequence type.")
  (letfn [(hf [x] (cond
                    (= :IpAddress (:type x)) (apply str (interpose "." (:value x)))
                    (= :Timeticks (:type x)) (.toString (Date. (long (:value x))))
                    (or (instance? BigInteger (:value x)) (instance? clojure.lang.BigInt (:value x))) (.toString (:value x))
                    (every? string? (:value x)) (apply str  (interpose "."  (map #(apply str %) (partition 2 (:value x)))))
                    :else (apply str (:value x))))]
    (reduce conj (for [x (map #(:value %) variable-bindings)] (hash-map (:value (first x)) (hf (second x)))))))

(defn vb2data [variable-bindings]
  (assert (every? #(= :sequence %) (map :type variable-bindings)) "There is something wrong with input parameter. Not every variable binding is a SNMP :sequence type.")
  (letfn [(hf [x] (cond
                    (= :IpAddress (:type x)) (apply str (interpose "." (:value x)))
                    (= :Timeticks (:type x)) (:value x) ;;(Date. (long (:value x)))
                    (or (instance? BigInteger (:value x)) (instance? clojure.lang.BigInt (:value x))) (.longValue (:value x))
                    (every? string? (:value x)) (apply str  (interpose "."  (map #(apply str %) (partition 2 (:value x)))))
                    (= :noSuchInstance (:type x)) :noSuchInstance
                    :else (:value x)))]
    (for [x (map #(:value %) variable-bindings)] {(:value (first x)) (hf (second x))})))

;; Function is ment to be used in repl for easier development
(defn show-variable-bindings [response]
  (doseq  [x  (-> response :message decompose-snmp-response :pdu :variable-bindings vb2str sort)]
    (let [o (split-oid (key x))
          v (val x)]
      (println (apply str "OID " (find-oid (first o)) ":" (oid2str (second o)) " = " v)))))

(defn resolve-oids-fn [x]
  (let [ot (split-oid (-> x keys first))
        o (keyword (apply str (interpose "." (conj  (map str (second ot)) (-> (find-oid (first ot)) name)))))
        v (-> x vals first)]
    (hash-map o v)))

;; Function resolves OID value if input is keyword
(defn resolve-oids [variable-bindings]
  (map resolve-oids-fn variable-bindings))

(defn get-variable-bindings [response]
  (-> response :message decompose-snmp-response :pdu :variable-bindings vb2data))

(defn get-rid [response]
  (-> response :message decompose-snmp-response :pdu :rid))

;; Following are functions for easier request interchange

(def rid-range [10000 500000])

(defn generate-request-id [] (+ (first rid-range) (rand-int (- (second rid-range) (first rid-range)))))


(defn get-new-rid [] (generate-request-id))


(defn open-line
  "Function returns a function that will genarate
  snmp requests based on community, host and request type.
  Only OID value can vary.

  Options are:
  :pdu-type [:get-bulk-request :get-request :get-next-request]
  :version [0 1 2]
  :port \"any\""
  [^String host ^String community & options]
  (let [o (if (nil? options) nil  (apply hash-map options))
        pdu-type (or (:pdu-type o) :get-bulk-request)
        version (or (:version o) 1)
        port (or (:port o) 161)]
    (fn [oids] {:message (compose-snmp-packet {:community community
                                               :version version
                                               :pdu ((pdu-type pdu-function) (get-new-rid) oids o)})
                :host (.getHostAddress (InetAddress/getByName host))
                :port port})))

(defn snmp-template
  "Function takes map of parameters that are optional. It returns
  SNMP template function with in form of {:message result :port port} that
  can be merged with host. Result is function that takes RID as input
  and returns composed packet with RID.

  Intention is to have one UDP channel for multicast UDP traffic."
  [{:keys [pdu-type version port community oids]
    :or {pdu-type :get-request
         version 1
         port 161
         community "public"
         oids [:system]}}]
  (fn [rid] {:message (compose-snmp-packet {:community community
                                            :version version
                                            :pdu ((pdu-type pdu-function) rid oids)})
             :port port}))


(defn tabelize-fix-length
  "Function returns single map that has keyword
  as fix-length input vector and a vector of values
  as map value. Basicly it filters OID from data"
  [data fix-oid]
  (let [oid (normalize-oid fix-oid)
        fd (filter #(= (take (count oid) (-> % keys first)) oid) data)]
    fd))

(defn tabelize-index
  [data fix-oid]
  (let [oid (normalize-oid fix-oid)
        fd (filter #(= (take (count oid) (-> % keys first)) oid) data)
        d (map #(vec (drop (count oid) (-> % keys first))) fd)]
    d))

(defn make-table
  "Function creates vector of maps that have
  keys of input paramater keywords. It filters data
  based on header-oids and in that order associates
  keys to found values.

  Data is supposed to be variable bindings data."
  [data header-oids keywords]
  (assert (= (count header-oids) (count keywords)) "Count heder-oids and keywords has to be equal")
  (let [indexes (sort (reduce into #{} (map #(tabelize-index data %) header-oids)))
        mapped-data (if-not (map? data) (reduce into {} data))
        mapping (apply hash-map (interleave header-oids keywords))
        get-values (fn [index]
                     (apply merge
                            (map #(hash-map
                                    (get mapping %)
                                    (get mapped-data (into (normalize-oid %) index))) header-oids)))]
    (map get-values indexes)))
