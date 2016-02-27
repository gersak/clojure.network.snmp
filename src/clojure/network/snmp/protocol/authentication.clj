(ns clojure.network.snmp.protocol.authentication)

(defprotocol AuthenticateMessage
  (authenticate-outgoing-message [this auth-key plain-message])
  (authenticate-incoming-message [this auth-key auth-params plain-message]))

(defprotocol MessageEncryption
  (encrypt-data [this encrypt-key data-to-encrypt])
  (decrypt-data [this decrypt-key private-parameters encrpyted-data]))

(defrecord User [username
                 security-name
                 auth-protocol
                 auth-key
                 auth-key-change
                 auth-key-owner-change
                 priv-protocol
                 priv-key
                 priv-key-change
                 priv-owner-key-change])

(defrecord SNMPEngine [snmp-engine-id
                       snmp-engine-boots
                       snmp-engine-time])
