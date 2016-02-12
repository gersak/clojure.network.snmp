(defproject kovacnica/clojure.network.snmp "0.1.0-SNAPSHOT"
  :description "SNMP library for Clojure"
  :url "http://example.com/FIXME"
  ;:aot :all
  ;:aot [seweg.protocols.netconf.TransportSSH
  ;      seweg.coders.snmp]
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :java-source-paths ["src/java"]
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/core.async "0.1.346.0-17112a-alpha"]
                 [org.clojure/math.numeric-tower "0.0.4"]])
