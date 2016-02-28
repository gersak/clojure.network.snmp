(ns clojure.network.snmp.client.simple
  (:require
    [clojure.core.async :as a :refer [go <!! <! go-loop take! put! alts!! chan]]
    [clojure.network.snmp.protocol
     :as s :refer :all]
    [clojure.network.snmp.coders.snmp :refer [BERCoder] :reload true])
  (:import
    [java.net
     SocketTimeoutException
     SocketException
     InetAddress
     DatagramPacket
     DatagramSocket]
    [ber BERUnit]))


(def ^{:dynamic true} *timeout* 2000)
(def ^{:dynamic true} *receive-packet-size* 2000)

(def ^:private default-options {:community "public"
                                :host "localhost"
                                :oids [[1 3 6 1 2 1 1]]
                                :timeout 2000
                                :pdu-type :get-bulk-request
                                :version :v2c})

;; Helpers

(defn- make-udp-socket
  ([& {:keys [timeout port] :or {timeout *timeout*}}]
   (if port
     (doto (DatagramSocket.) (.setSoTimeout timeout) (.setPort port))
     (doto (DatagramSocket.) (.setSoTimeout timeout)))))

(defn- generate-udp-packet
  ([^bytes byte-seq ^String host] (generate-udp-packet byte-seq host 161))
  ([^bytes byte-seq ^String host port]
   (DatagramPacket. byte-seq (count byte-seq) (InetAddress/getByName host) port)))

(defn- generate-blank-packet
  ([] (generate-blank-packet *receive-packet-size*))
  ([size] (DatagramPacket. (byte-array size) (int size))))

(defn make-simple-rid-store []
  (let [rids (atom #{})]
    (reify
      RIDStoreProtocol
      (create-rid [_] (let [rid (first (drop-while @rids (repeatedly (partial rand-int 100000))))]
                        (swap! rids conj rid)
                        rid))
      (verify-rid [_ rid] (if (@rids rid)
                            (do
                              (swap! rids disj rid)
                              true)
                            false))
      (pending-rids [_] @rids))))

(defn make-mapped-rid-store
  "Function returns reified RIDStore in form of
  hash-map where keys are RIDs and vals are sent
  SNMP requests."
  []
  (let [rids (atom {})]
    (reify
      RIDStoreProtocol
      (create-rid [_ req] (let [rid (first (drop-while @rids (repeatedly (partial rand-int 100000))))]
                            (swap! rids assoc rid req)
                            rid))
      (verify-rid [_ rid]
        (if (contains? @rids rid)
          (do
            (swap! rids dissoc rid)
            true)
          false))
      (verify-rid [_ rid req]
        (if (= req (get @rids rid))
          (do
            (swap! rids dissoc rid)
            true)
          false))
      (pending-rids [_] @rids))))


(defn- get-oids-map [oids]
  (for [x oids] {:type :sequence
                 :value [{:type :OID :value x}
                         {:type :Null}]}))

(defn open-line
  "Returns returns constructed reifed object that can be used to
  communicate through SNMP with remote host.
  Checkout SNMPSocketLineProtocol and SNMPLineQueryProtocol"
  ([{:keys [host port pdu-type composer encoder timeout]
     :or {host "localhost"
          port 161
          pdu-type :get-bulk-request
          timeout 2000
          composer (make-snmp-composer {:version :v2c :community "public"})
          encoder BERCoder} :as options}]
   (assert (#{:get-request :get-bulk-request :get-next-request} pdu-type) (str "Only :get-request, :get-next-request, :get-bulk-request are supported"))
   (let [snmp-rid-store (make-simple-rid-store)
         socket (doto (DatagramSocket.) (.setSoTimeout timeout) (.setBroadcast false))
         line (reify
                SNMPSocketLineProtocol
                (connect [_ new-host new-port]
                  (do
                    (.disconnect socket)
                    (.connect socket (java.net.InetAddress/getByName new-host) new-port)))
                (connect [this new-host] (.connect this new-host 161))
                (closed? [_] (.isClosed socket))
                (close [_] (.close socket))
                (get-host [_] (.. socket getInetAddress getHostAddress))
                (get-port [_] (.getPort socket))
                (send-over-line [this snmp-message]
                  (if (closed? this)
                    (throw (SocketException. " Socket has been closed.")))
                  (try
                    (let [byte-message (generate-udp-packet
                                         (snmp-encode encoder snmp-message)
                                         (get-host this)
                                         (get-port this))
                          rp (generate-blank-packet)]
                      (.send socket byte-message)
                      (.receive socket rp)
                      (.getData rp)
                      (snmp-decode encoder (.getData rp)))
                    (catch SocketTimeoutException e nil)
                    (catch SocketException e nil)
                    (catch Exception e (do
                                         (println "input: " snmp-message)
                                         (.printStackTrace e)))))
                SNMPLineQueryProtocol
                (query-oids [this oids]
                  (let [rid (create-rid snmp-rid-store)
                        pdu (make-snmp-pdu pdu-type rid (get-oids-map oids) options)
                        message (snmp-compose-message composer pdu)
                        response (send-over-line this message)]
                    (when-let [returned-pdu (snmp-decompose-message composer response)]
                      (assert (= (:type returned-pdu) :response) (str "Returned PDU type is " (:type returned-pdu) ". Expecting :response type."))
                      (-> returned-pdu :value (nth 3) :value vb2data)))))]
     (connect line host port)
     line)))



;; Usable functions
(defn poke [host community & {:keys [timeout oids]
                              :or {timeout *timeout*
                                   oids [[1 3 6 1 2 1 1 1 0]]}}]
  (let [line (open-line {:host host :community community :pdu-type :get-request})]
    (try
      (connect line host)
      (query-oids line oids)
      (finally (close line)))))

(def ^:private default-snmp-get-composer-options
  {:community "public"
   :version :v2c})

;; SNMP-GET
(defn snmp-get
  "Function executes get-next request towards
  target host depending on oids and options configuration.
  Options can be:
  :timeout
  :error-type
  :errot-index
  :version
  :community
  :security-level
  :authentication-protocol
  :privacy-protocol
  :privacy-password
  :context"
  [host & {:keys [oids] :or {oids [[1 3 6 1 2 1 1 1 0]]} :as options}]
  (let [options (merge default-snmp-get-composer-options options)
        line (open-line (assoc options :host host :pdu-type :get-request :composer (make-snmp-composer options)))]
    (try
      (connect line host)
      (query-oids line oids)
      (finally (close line)))))

(defn snmp-get-next
  "Function executes get-next request towards
  target host depending on oids and options configuration.
  Options can be:
  :timeout
  :error-type
  :errot-index
  :version
  :community
  :security-level
  :authentication-protocol
  :privacy-protocol
  :privacy-password
  :context"
  [host & {:keys [oids] :or {oids [[1 3 6 1 2 1 1 1]]} :as options}]
  (let [options (merge default-snmp-get-composer-options options)
        line (open-line (assoc options :host host :pdu-type :get-next-request :composer (make-snmp-composer options)))]
    (try
      (connect line host)
      (query-oids line oids)
      (finally (close line)))))

(defn snmp-get-bulk
  "Function executes bulk request towards
  target host depending on oids and options configuration.
  Options can be:
  :timeout
  :non-repetitors
  :max-repetitions
  :version
  :community
  :security-level
  :authentication-protocol
  :privacy-protocol
  :privacy-password
  :context"
  [host & {:keys [oids] :or {oids [[1 3 6 1 2 1 1 1]]} :as options}]
  (let [options (merge default-snmp-get-composer-options options)
        line (open-line (assoc options :host host :pdu-type :get-bulk-request :composer (make-snmp-composer options)))]
    (try
      (connect line host)
      (query-oids line oids)
      (finally (close line)))))



(defn corelate-oid-data [variable-bindings oids]
  (let [child? (fn [vb]
                 (some #(if (is-child-of-oid? (:oid vb) %) %) oids))]
    (map #(sort-by :oid (val %)) (group-by child?) variable-bindings)))

(defn snmp-walk
  "Function executes series of snmp-get request towards
  target host depending on oids and options configuration.
  Options can be:
  :timeout
  :error-type
  :errot-index
  :version
  :community
  :security-level
  :authentication-protocol
  :privacy-protocol
  :privacy-password
  :context"
  [host & {:keys [oids] :or {oids [[1 3 6 1 2 1 1]]} :as options}]
  (let [options (merge default-snmp-get-composer-options options)
        line (open-line (assoc options :host host :pdu-type :get-next-request :composer (make-snmp-composer options)))
        child? (fn [vb]
                 (some #(if (is-child-of-oid? (:oid vb) %) %) oids))]
    (try
      (connect line host)
      (loop [current-response (query-oids line oids)
             end-result []]
        (let [next-request-oids (map :oid (filter child? current-response))]
          (if (empty? next-request-oids) end-result
            (recur (query-oids line next-request-oids) (concat end-result (filter child? current-response)))))))))

(defn snmp-bulk-walk
  "Function executes series of bulk request towards
  target host depending on oids and options configuration.
  Options can be:
  :timeout
  :non-repetitors
  :max-repetitions
  :version
  :community
  :security-level
  :authentication-protocol
  :privacy-protocol
  :privacy-password
  :context"
  [host & {:keys [oids] :or {oids [[1 3 6 1 2 1 1]]} :as options}]
  (let [options (merge default-snmp-get-composer-options options)
        line (open-line (assoc options :host host :pdu-type :get-bulk-request :composer (make-snmp-composer options)))
        child? (fn [vb oids]
                 (some #(if (is-child-of-oid? (:oid vb) %) %) oids))]
    (try
      (connect line host)
      (for [oid oids :let [oids [oid]]]
        (loop [current-response (query-oids line oids)
               end-result []]
          (let [next-request-oids (when (child? (:oid (last current-response)) oids) (:oid (last current-response)))]
            (if (empty? next-request-oids) (concat end-result (filter #(child? % oids) current-response))
              (recur (query-oids line next-request-oids) (concat end-result (filter #(child? % oids) current-response))))))))))
