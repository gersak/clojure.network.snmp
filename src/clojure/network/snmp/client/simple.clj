(ns clojure.network.snmp.client.simple
  (:require
    [clojure.core.async :as a :refer [go <!! <! go-loop take! put! alts!! chan]]
    [clojure.network.snmp
     [protocol :as s :refer [is-child-of-oid?
                             open-line
                             generate-request-id
                             make-table]]])
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

;; Helpers
(defn- get-variable-bindings "TODO" [& args] )
(defn- snmp-template "TODO" [& args] )

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

(defn- send-sync [#^DatagramSocket client ^DatagramPacket packet]
  (let [rp (generate-blank-packet)]
    (.send client packet)
    (.receive client rp)
    {:host (.getHostAddress (.getAddress rp))
     :port (.getPort rp)
     :message (.getData rp)}))

(defn- process-udp [{:keys [message host port timeout]
                      :as prepared-packet
                      :or {port 161 timeout *timeout*}}]
  (when-let [client (make-udp-socket :timeout timeout)]
    (try
      (let [packet (generate-udp-packet message host)]
        (send-sync client packet))
      (catch SocketTimeoutException e nil)
      (catch Exception e (do
                           (println "input: " prepared-packet)
                           (.printStackTrace e)))
      (finally (.close client)))))




;; Usable functions

(defn snmp-get [& {:keys [host community timeout oids port version]
                   :or {timeout *timeout*
                        port 161
                        host "localhost"
                        community "public"
                        version :v2c
                        oids [[1 3 6 1 2 1 1 1 0]]}
                   :as options}]
  (let [line (open-line (assoc options
                               :pdu-type :get-request
                               :community community
                               :version version
                               :port port))
        {host_ :host response :message} (process-udp {:host host
                                                      :timeout timeout
                                                      :message (s/encode line {:oids oids})
                                                      :port port})]
    (s/decode line response)))


(defn snmp-get-next [& {:keys [host community timeout oids port version]
                        :or {timeout *timeout*
                             port 161
                             host "localhost"
                             community "public"
                             version :v2c
                             oids [[1 3 6 1 2 1 1 1 0]]}
                        :as options}]
  (let [line (open-line (assoc options
                               :pdu-type :get-next-request
                               :community community
                               :version version
                               :port port))
        {host_ :host response :message} (process-udp {:host host
                                                      :community community
                                                      :timeout timeout
                                                      :message (s/encode line {:oids oids})
                                                      :port port})]
    (s/decode line response)))

(defn snmp-bulk-get [& {:keys [host community timeout oids port version]
                        :or {timeout *timeout*
                             port 161
                             host "localhost"
                             community "public"
                             version :v2c
                             oids [[1 3 6 1 2 1 1 1]]}
                        :as options}]
  (let [line (open-line (assoc options
                               :pdu-type :get-bulk-request
                               :community community
                               :version version
                               :port port))
        {host_ :host response :message} (process-udp {:host host
                                                      :community community
                                                      :timeout timeout
                                                      :message (s/encode line {:oids oids})
                                                      :port port})]
    (s/decode line response)))



(defn snmp-get-first
  "Returns first valid found value of oids input arguments."
  ([version host community & oids]
   (when-let [client (make-udp-socket)]
     (let [oids (vec oids)
           get-fn (open-line host community :pdu-type :get-next-request :version version)
           transmition-fn (fn [oids]
                            (let [ld (get-fn :oids oids)
                                  p (generate-udp-packet (coders/snmp-encode (:message ld)) host)]
                              (get-variable-bindings (send-sync client p))))
           valid-oids (fn [results oids]
                        (let [get-key #(apply key %)]
                          (remove nil?
                                  (set (for [r results ok oids :let [rk (get-key r)]]
                                         (let [c (dec (min (count rk) (count ok)))]
                                           (if (= (take c rk) (take c ok)) r)))))))
           checkfn (fn [x]
                     (let [v (apply val x)]
                       (cond
                         (coll? v) (seq v)
                         (string? v) (boolean (seq v))
                         :else (boolean v))))]
       (try
         (let [vb-initial (transmition-fn oids)]
           (loop [vb (filter checkfn vb-initial)
                  not-found (remove checkfn vb-initial)]
             (when (some (comp not nil?) vb)
               (if (empty? not-found)
                 (sort-by #(apply key %) (valid-oids vb oids))
                 (let [new-vb (transmition-fn (map #(apply key %) not-found))
                       found-vb (filter checkfn new-vb)
                       empty-vb (valid-oids (remove checkfn new-vb) oids)]
                   (recur (into vb found-vb) empty-vb))))))
         (catch Exception e nil)
         (finally (.close client)))))))


(defn snmp-bulk-get [version host community & oids]
  (let [oids (vec oids)
        get-fn (open-line {:host host :community community :pdu-type :get-bulk-request :version version})]
    (-> (get-fn :oids oids) process-udp get-variable-bindings)))


;; Walking functions
(defn snmp-bulk-walk
  "Function tries to walk OID tree as far as response
    contains input oid value. If it fails or times out
    function will return nil. Input OIDs accepts vector
    of OID values. Either as keywords or vectors.

    Default timeout is 2s. "
  ([host community oids] (snmp-bulk-walk host community oids 2000))
  ([host community oids timeout]
   (when-let [c (make-udp-socket :timeout timeout)]
     (try
       (let [bulk-fn (open-line {:host host
                                 :community community
                                 :version :v2c
                                 :pdu-type :get-bulk-request})]
         (letfn [(valid-vb? [vb]
                   (let [vb-oid (-> vb first key)]
                     (some #(is-child-of-oid? vb-oid %) oids)))
                 (send-fn [oid]
                   (.send c (generate-udp-packet (coders/snmp-encode
                                                  (:message
                                                   (bulk-fn :oids [oid]))) host)))
                 (receive-fn []
                   (let [p (generate-blank-packet)]
                     (.receive c p)
                     {:host (.getHostAddress (.getAddress p))
                      :port (.getPort p)
                      :message (coders/snmp-decode (.getData p))}))]
           (doseq [x oids] (send-fn x))
           (loop [r []]
             (let [p (receive-fn)
                   vb (get-variable-bindings p)
                   last-oid (-> vb last keys first)]
               (if (valid-vb? (last vb))
                 (do
                   (send-fn last-oid)
                   (recur (into r (filter valid-vb? vb))))
                 (into r (filter valid-vb? vb)))))))
       #_(catch Exception e )
       (catch Exception e (.printStackTrace e))
       (finally (.close c))))))


(defn snmp-walk
  ([host community oids] (snmp-walk host community oids 2000))
  ([host community oids timeout]
   (with-open [c (make-udp-socket :timeout timeout)]
     (try
       (let [next-fn (open-line {:host      host
                                 :version   :v2c
                                 :community community
                                 :pdu-type  :get-next-request})]
         (letfn [(valid-vb? [vb]
                   (let [vb-oid (-> vb first key)]
                     (some #(is-child-of-oid? vb-oid %) oids)))
                 (send-fn [oid]
                   (.send c (generate-udp-packet (coders/snmp-encode
                                                  (:message
                                                   (next-fn :oids [oid]))) host)))
                 (receive-fn []
                   (let [p (generate-blank-packet)]
                     (.receive c p)
                     {:host    (.getHostAddress (.getAddress p))
                      :port    (.getPort p)
                      :message (coders/snmp-decode (.getData p))}))]
           (doseq [x oids] (send-fn x))
           (loop [r []]
             (let [p        (receive-fn)
                   vb       (get-variable-bindings p)
                   last-oid (-> vb last keys first)]
               (if (valid-vb? (last vb))
                 (do
                   (send-fn last-oid)
                   (recur (into r (filter valid-vb? vb))))
                 (into r (filter valid-vb? vb)))))))
       (catch java.net.SocketTimeoutException e nil)
       (catch Exception e (.printStackTrace e))))))

(defn shout
  "Function \"shouts\" oids to collection of hosts. It openes one
   port through which it sends UDP packets to different targets and
   waits for their response.

   Sort of multicast traffic."
  [hosts & {:keys [community port version oids pdu-type send-interval timeout]
            :or {send-interval 5
                 timeout *timeout*}
            :as receiver-options}]
  (with-open [c (make-udp-socket :timeout timeout)]
    (let [template-fn (snmp-template receiver-options)
          result (atom nil)
          packets (map #(merge {:host %} (template-fn (generate-request-id))) hosts)
          receive-chan (chan)]
      (letfn [(send-fn [{m :message h :host}]
                (when-not (.isClosed c)
                  (try
                    (let [p (generate-udp-packet (coders/snmp-encode m) h)]
                      (.send c p))
                    (catch Exception e
                      (println "Couldn't generate and send udp-packet to host " h "\nPACKET:\n" (pr-str m))))))
              (receive-fn []
                (try
                  (let [p (generate-blank-packet)]
                    (.receive c p)
                    {:host (.getHostAddress (.getAddress p))
                     :port (.getPort p)
                     :message (coders/snmp-decode (.getData p))})
                  (catch SocketTimeoutException e nil)
                  (catch SocketException e nil)))]
        (try
          (go
            (doseq [x packets]
              (send-fn x)
              (<! (a/timeout send-interval))))
          (loop [result nil]
            (if-let [rp (receive-fn)]
              (recur (conj result (hash-map :host (:host rp) :bindings (-> rp get-variable-bindings))))
              result))
          (catch Exception e (do
                               (.printStackTrace e))))))))

(defn shout-some [hosts & {:keys [timeout oids community version send-interval timeout port pdu-type]
                           :or {timeout *timeout*
                                community "public"
                                port 161
                                pdu-type :get-next-request
                                send-interval 2}
                           :as receiver-options}]
  (let [receiver-options (if (:oids receiver-options) receiver-options
                             (assoc receiver-options :oids [[1 3 6 1 2 1 1 2 0] [1 3 6 1 2 1 1 5 0] [1 3 6 1 2 1 1 6 0] [1 3 6 1 2 1 47 1 1 1 1 11 1] [1 3 6 1 2 1 1 3 0]]))]
    (when (coll? hosts)
      (with-open [c (make-udp-socket :timeout timeout)]
        (let [template-fn (snmp-template receiver-options)
              result (atom nil)
              packets (map #(merge {:host %} (template-fn (generate-request-id))) hosts)]
          (letfn [(send-fn [{m :message h :host}]
                    (when-not (.isClosed c)
                      (try
                        (let [p (generate-udp-packet (coders/snmp-encode m) h)]
                          (.send c p))
                        (catch Exception e
                          (do
                            (println "Couldn't generate and send udp-packet to host " h "\nPACKET:\n" (pr-str m))
                            (.printStackTrace e))))))
                  (receive-fn []
                    (let [p (generate-blank-packet)]
                      (.receive c p)
                      {:host (.getHostAddress (.getAddress p))
                       :port (.getPort p)
                       :message (coders/snmp-decode (.getData p))}))]
            (try
              (doseq [x packets]
                (send-fn x))
              (when-let [rp (receive-fn)]
                {:host (:host rp)
                 :bindings (-> rp get-variable-bindings)})
              (catch SocketTimeoutException e @result)
              (catch SocketException e @result)
              (catch Exception e (do
                                   (.printStackTrace e))))))))))
