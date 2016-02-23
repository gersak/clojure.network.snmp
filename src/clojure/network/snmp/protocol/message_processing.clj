(in-ns 'clojure.network.snmp.protocol)
;; RFC 3412
;; Section .5

(def rid-range [10000 500000])

(defn generate-request-id [] (+ 10000 (rand-int 400000)))

(defn set-request-id [packet rid]
  (update packet :value
          #(update % 0 {:type :Integer :value rid})))

(defn get-request-id [packet rid]
  (-> packet :value first :value))

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
  :version [:v1 :v2c :v3]
  :port \"any\""
  open-line-resolver)

(defmethod open-line :default [{:keys [version]}]
  (throw (Exception. (str "Unknown SNMP version: " version))))

(defmethod open-line :v1 [{:keys [host community pdu-type version port] :as options}]
  (let [pdu-type (or pdu-type :get-bulk-request)
        version (or version :v2c)
        port (or port 161)]
    (fn [& {:keys [rid oids] :or {rid (generate-request-id)}}]
      {:type :sequence
       :value [{:type :Integer :value 0}
               {:type :OctetString :value community}
               ((bind-request-type options) rid oids)]})))

(defmethod open-line :v2c [{:keys [host community pdu-type port] :as options}]
  (let [pdu-type (or pdu-type :get-bulk-request)
        port (or port 161)]
    (fn [& {:keys [rid oids] :or {rid (generate-request-id)}}]
      {:type :sequence
       :value [{:type :Integer :value 1}
               {:type :OctetString :value community}
               ((bind-request-type options) rid oids)]})))

(defmethod open-line :v3 [{:keys [host
                                  community
                                  port
                                  pdu-type
                                  security-model
                                  security-name
                                  security-level
                                  context-engine-id
                                  context-name
                                  message-max-size
                                  message-flags
                                  message-security-model
                                  message-id
                                  message-security-parameters]
                           :or {port 161
                                version 1}
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
