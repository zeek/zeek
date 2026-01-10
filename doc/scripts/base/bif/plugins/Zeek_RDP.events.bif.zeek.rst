:tocdepth: 3

base/bif/plugins/Zeek_RDP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= =================================================================================
:zeek:id:`rdp_begin_encryption`: :zeek:type:`event`           Generated when an RDP session becomes encrypted.
:zeek:id:`rdp_client_cluster_data`: :zeek:type:`event`        Generated for client cluster data packets.
:zeek:id:`rdp_client_core_data`: :zeek:type:`event`           Generated for MCS client requests.
:zeek:id:`rdp_client_network_data`: :zeek:type:`event`        Generated for Client Network Data (TS_UD_CS_NET) packets
:zeek:id:`rdp_client_security_data`: :zeek:type:`event`       Generated for client security data packets.
:zeek:id:`rdp_connect_request`: :zeek:type:`event`            Generated for X.224 client requests.
:zeek:id:`rdp_gcc_server_create_response`: :zeek:type:`event` Generated for MCS server responses.
:zeek:id:`rdp_native_encrypted_data`: :zeek:type:`event`      Generated for each packet after RDP native encryption begins
:zeek:id:`rdp_negotiation_failure`: :zeek:type:`event`        Generated for RDP Negotiation Failure messages.
:zeek:id:`rdp_negotiation_response`: :zeek:type:`event`       Generated for RDP Negotiation Response messages.
:zeek:id:`rdp_server_certificate`: :zeek:type:`event`         Generated for a server certificate section.
:zeek:id:`rdp_server_security`: :zeek:type:`event`            Generated for MCS server responses.
:zeek:id:`rdpeudp_data`: :zeek:type:`event`                   Generated when for data messages exchanged after a RDPEUDP connection establishes
:zeek:id:`rdpeudp_established`: :zeek:type:`event`            Generated when RDPEUDP connections are established (both sides SYN)
:zeek:id:`rdpeudp_syn`: :zeek:type:`event`                    Generated for RDPEUDP SYN UDP Datagram
:zeek:id:`rdpeudp_synack`: :zeek:type:`event`                 Generated for RDPEUDP SYNACK UDP Datagram
============================================================= =================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: rdp_begin_encryption
   :source-code: base/protocols/rdp/main.zeek 262 272

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated when an RDP session becomes encrypted.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param security_protocol: The security protocol being used for the session.

.. zeek:id:: rdp_client_cluster_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 111 111

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientClusterData`)

   Generated for client cluster data packets.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param data: The data contained in the client security data structure.

.. zeek:id:: rdp_client_core_data
   :source-code: base/protocols/rdp/main.zeek 190 216

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientCoreData`)

   Generated for MCS client requests.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param data: The data contained in the client core data structure.

.. zeek:id:: rdp_client_network_data
   :source-code: base/protocols/rdp/main.zeek 218 231

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, channels: :zeek:type:`RDP::ClientChannelList`)

   Generated for Client Network Data (TS_UD_CS_NET) packets


   :param c: The connection record for the underlying transport-layer session/flow.


   :param channels: The channels that were requested

.. zeek:id:: rdp_client_security_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 95 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientSecurityData`)

   Generated for client security data packets.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param data: The data contained in the client security data structure.

.. zeek:id:: rdp_connect_request
   :source-code: base/protocols/rdp/main.zeek 169 174

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`)

   Generated for X.224 client requests.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param cookie: The cookie included in the request; empty if no cookie was provided.


   :param flags: The flags set by the client.

.. zeek:id:: rdp_gcc_server_create_response
   :source-code: base/protocols/rdp/main.zeek 233 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`count`)

   Generated for MCS server responses.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param result: The 8-bit integer representing the GCC Conference Create Response result.

.. zeek:id:: rdp_native_encrypted_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, len: :zeek:type:`count`)

   Generated for each packet after RDP native encryption begins


   :param c: The connection record for the underlying transport-layer session/flow.


   :param orig: True if the packet was sent by the originator of the connection.


   :param len: The length of the encrypted data.

.. zeek:id:: rdp_negotiation_failure
   :source-code: base/protocols/rdp/main.zeek 183 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, failure_code: :zeek:type:`count`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, failure_code: :zeek:type:`count`)

   Generated for RDP Negotiation Failure messages.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param failure_code: The failure code sent by the server.


   :param flags: The flags set by the server.

.. zeek:id:: rdp_negotiation_response
   :source-code: base/protocols/rdp/main.zeek 176 181

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated for RDP Negotiation Response messages.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param security_protocol: The security protocol selected by the server.


   :param flags: The flags set by the server.

.. zeek:id:: rdp_server_certificate
   :source-code: base/protocols/rdp/main.zeek 248 260

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cert_type: :zeek:type:`count`, permanently_issued: :zeek:type:`bool`)

   Generated for a server certificate section.  If multiple X.509
   certificates are included in chain, this event will still
   only be generated a single time.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param cert_type: Indicates the type of certificate.


   :param permanently_issued: Value will be true is the certificate(s) is permanent on the server.

.. zeek:id:: rdp_server_security
   :source-code: base/protocols/rdp/main.zeek 240 246

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, encryption_method: :zeek:type:`count`, encryption_level: :zeek:type:`count`)

   Generated for MCS server responses.


   :param c: The connection record for the underlying transport-layer session/flow.


   :param encryption_method: The 32-bit integer representing the encryption method used in the connection.


   :param encryption_level: The 32-bit integer representing the encryption level used in the connection.

.. zeek:id:: rdpeudp_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated when for data messages exchanged after a RDPEUDP connection establishes


   :param c: The connection record for the underlying transport-layer session/flow.


   :param is_orig: Whether the data was sent by the originator or responder of the connection.


   :param version: Whether the connection is RDPEUDP1 or RDPEUDP2


   :param data: The payload of the packet. This is probably very non-performant.

.. zeek:id:: rdpeudp_established
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`)

   Generated when RDPEUDP connections are established (both sides SYN)


   :param c: The connection record for the underlying transport-layer session/flow.


   :param version: Whether the connection is RDPEUDP1 or RDPEUDP2

.. zeek:id:: rdpeudp_syn
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 7 7

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for RDPEUDP SYN UDP Datagram


   :param c: The connection record for the underlying transport-layer session/flow.

.. zeek:id:: rdpeudp_synack
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 13 13

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for RDPEUDP SYNACK UDP Datagram


   :param c: The connection record for the underlying transport-layer session/flow.


