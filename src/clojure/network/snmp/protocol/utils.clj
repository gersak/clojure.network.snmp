(in-ns 'clojure.network.snmp.protocol)


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
  (assert (every? #(= :sequence %) (map :type variable-bindings)) "There is something wrong with input parameter. Not every variable binding is of SNMP :sequence type.")
  (letfn [(hf [x] (cond
                    (= :IpAddress (:type x)) (apply str (interpose "." (:value x)))
                    (= :Timeticks (:type x)) (:value x) ;;(Date. (long (:value x)))
                    (or (instance? BigInteger (:value x)) (instance? clojure.lang.BigInt (:value x))) (.longValue (:value x))
                    (every? string? (:value x)) (apply str  (interpose "."  (map #(apply str %) (partition 2 (:value x)))))
                    (= :noSuchInstance (:type x)) :noSuchInstance
                    :else (:value x)))]
    (for [x (map #(:value %) variable-bindings)] (VariableBinding. (:value (first x)) (hf (second x))))))

;; Following are functions for easier request interchange

(defn generate-request-id
  ([] (generate-request-id nil))
  ([used-ids] (if used-ids
                (loop [rid (+ 10000 (rand-int 400000))]
                  (if (contains? used-ids rid) (recur (+ 10000 (rand-int 400000)))
                    rid)))))

(defmulti bind-request-type (fn [{:keys [pdu-type]}] pdu-type))

(defmethod bind-request-type :default [{:keys [pdu-type]}]
  (throw (Exception. (str "Unknown SNMP PDU type: " pdu-type))))

(defmethod bind-request-type :get-request [options]
  (fn [rid oids]
    (get-request-pdu rid oids options)))

(defmethod bind-request-type :get-next-request [options]
  (fn [rid oids]
    (get-next-request-pdu rid oids options)))

(defmethod bind-request-type :get-bulk-request [options]
  (fn [rid oids]
    (get-bulk-pdu rid oids options)))

(defn- open-line-resolver [{:keys [version] :as options}]
  (or
    (#{:v1 :v2c :v3} version)
    ({0 :v1 1 :v2c 3 :v3} version)
    ({"v1" :v1 "v2c" :v2c "v3" :v3} version)))


(defmulti open-line
  "Function returns a function that will genarate
  snmp requests based on community, host and request type.
  Only OID value can vary.

  Options are:
  :pdu-type [:get-bulk-request :get-request :get-next-request]
  :community \"public\"
  :version [:v1 :v2c :v3]
  :port \"any\""
  open-line-resolver)


(defmethod open-line :default [{:keys [version]}]
  (throw (Exception. (str "Unknown SNMP version: " version))))


(defmethod open-line :v1 [{:keys [community pdu-type port version] :as options}]
  (let [pdu-type (or pdu-type :get-bulk-request)
        port (or port 161)
        sent-requests_ (atom #{})]
    (assert (#{:snmp-get-request :set-request :trap :response} pdu-type) (str "SNMPv1 doesn't support PDU type: " pdu-type))
    (reify
      SNMPChannel
      (encode [_ {:keys [rid oids] :or {rid (generate-request-id @sent-requests_)}}]
        (do
          (if (@sent-requests_ rid)
            (throw (Exception. (str "packet with RID: " rid " already exists and is still pending.")))
            (swap! sent-requests_ conj rid))
          (snmp-encode
            {:type :sequence
             :value [{:type :Integer :value 0}
                     {:type :OctetString :value community}
                     ((bind-request-type options) rid oids)]})))
      (decode [_ received-bytes]
        (when-not (nil? received-bytes)
          (let [snmp-packet-tree (snmp-decode received-bytes)
                pdu-type (-> snmp-packet-tree :value (nth 2))
                version_ (-> snmp-packet-tree :value first :value)
                community_ (-> snmp-packet-tree :value second :value)
                pdu (-> snmp-packet-tree :value (nth 2))
                rid (-> pdu :value first :value)
                error-index (-> pdu :value (nth 2) :value)
                error-type (get error-type (-> pdu :value (nth 1) :value))
                variable-bindings (-> pdu :value (nth 3) :value)]
            (assert error-index (str "Error received: " error-type))
            (assert (= 0 version_) (str "Received response with different version."))
            (assert (= community community_) (str "Received response with different community."))
            (if-not (@sent-requests_ rid)
              (throw (Exception. (str "received packet with RID: " rid " that was not sent to host from this channel.")))
              (do
                (swap! sent-requests_ disj rid)
                (filter :oid (vb2data variable-bindings))))))))))



(defmethod open-line :v2c [{:keys [community pdu-type port version] :as options}]
  (let [pdu-type (or pdu-type :get-bulk-request)
        port (or port 161)
        sent-requests_ (atom #{})]
    (reify
      SNMPChannel
      (encode [_ {:keys [rid oids] :or {rid (generate-request-id @sent-requests_)}}]
        (if (@sent-requests_ rid)
            (throw (Exception. (str "packet with RID: " rid " already exists and is still pending.")))
            (swap! sent-requests_ conj rid))
        (snmp-encode
            (hash-map
              :type :sequence
              :value [{:type :Integer :value 1}
                      {:type :OctetString :value community}
                      ((bind-request-type options) rid oids)])))
      (decode [_ received-bytes]
        (when-not (nil? received-bytes)
          (let [snmp-packet-tree (snmp-decode received-bytes)
                pdu-type (-> snmp-packet-tree :value (nth 2))
                version_ (-> snmp-packet-tree :value first :value)
                community_ (-> snmp-packet-tree :value second :value)
                pdu (-> snmp-packet-tree :value (nth 2))
                rid (-> pdu :value first :value)
                error-index (-> pdu :value (nth 2) :value)
                error-type (get error-type (-> pdu :value (nth 1) :value))
                variable-bindings (-> pdu :value (nth 3) :value)]
            (assert error-index (str "Error received: " error-type))
            (assert (= 1 version_) (str "Received response with different version."))
            (assert (= community community_) (str "Received response with different community."))
            (if-not (@sent-requests_ rid)
              (throw (Exception. (str "received packet with RID: " rid " that was not sent to host from this channel.")))
              (do
                (swap! sent-requests_ disj rid)
                (filter :oid (vb2data variable-bindings))))))))))

(defmethod open-line :v3 [{:keys [host community port pdu-type
                                  message-max-size
                                  message-flags
                                  message-security-model
                                  message-id
                                  message-security-parameters
                                  context-engine-id context-name]
                           :or {port 161
                                version 3}
                           :as options}]
  (let [{:keys [message-authoritive-engine-id
                message-authoritive-engine-boots
                message-authoritive-engine-time
                message-user-name
                message-authentication-parameters
                message-privacy-parameters]} message-security-parameters
        pdu-type (or pdu-type :get-bulk-request)
        port (or port 161)]
    (assert (and (string? message-user-name) (seq message-user-name)) "message-user-name not specified in message-security-parameters!")
    (assert (and (string? message-authoritive-engine-id) (seq message-authoritive-engine-id)) "message-authoritive-engine-id not specified in message-security-parameters!")
    (assert (and (string? message-authoritive-engine-id) (seq message-authoritive-engine-id)) "message-authoritive-engine-id not specified in message-security-parameters!")
    (fn [& {:keys [rid oids] :or {rid (generate-request-id)}}]
      {:message {:type :sequence
                 :value [{:type :OctetString :value message-authoritive-engine-id}
                         {:type :Integer :value message-authoritive-engine-boots}
                         {:type :Integer :value message-authoritive-engine-time}
                         {:type :OctetString :value message-user-name}
                         {:type :OctetString :value message-authentication-parameters}
                         {:type :OctetString :value message-privacy-parameters}
                         ((bind-request-type options) rid oids)]}
       :host host
       :port port}))
  (throw (Exception. "SNMP version 3 is not jet supported.")))




(defn tabelize-fix-length
  "Function returns single map that has keyword
  as fix-length input vector and a vector of values
  as map value. Basicly it filters OID from data"
  [data oid]
  (let [fd (filter #(= (take (count oid) (-> % keys first)) oid) data)]
    fd))

(defn tabelize-index
  [data oid]
  (let [fd (filter #(= (take (count oid) (-> % keys first)) oid) data)
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
                                    (get mapped-data (into % index))) header-oids)))]
    (map get-values indexes)))

(defn is-child-of-oid?
  "Test function that examines if OID is child of parent.
  Input values can be keywords or vectors and combination."
  [oid parent]
  (if (> (count parent) (count oid))
    false
    (= (take (count parent) oid) parent)))
