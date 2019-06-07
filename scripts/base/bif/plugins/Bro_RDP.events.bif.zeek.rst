:tocdepth: 3

base/bif/plugins/Bro_RDP.events.bif.zeek
========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= ============================================================
:zeek:id:`rdp_begin_encryption`: :zeek:type:`event`           Generated when an RDP session becomes encrypted.
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
============================================================= ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: rdp_begin_encryption

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated when an RDP session becomes encrypted.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol being used for the session.

.. zeek:id:: rdp_client_core_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientCoreData`)

   Generated for MCS client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :data: The data contained in the client core data structure.

.. zeek:id:: rdp_client_network_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, channels: :zeek:type:`RDP::ClientChannelList`)

   Generated for Client Network Data (TS_UD_CS_NET) packets
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :channels: The channels that were requested

.. zeek:id:: rdp_client_security_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientSecurityData`)

   Generated for client security data packets.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :data: The data contained in the client security data structure.

.. zeek:id:: rdp_connect_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`)

   Generated for X.224 client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cookie: The cookie included in the request.

.. zeek:id:: rdp_gcc_server_create_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: The 8-bit integer representing the GCC Conference Create Response result.

.. zeek:id:: rdp_native_encrypted_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, len: :zeek:type:`count`)

   Generated for each packet after RDP native encryption begins
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :orig: True if the packet was sent by the originator of the connection.
   

   :len: The length of the encrypted data.

.. zeek:id:: rdp_negotiation_failure

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, failure_code: :zeek:type:`count`)

   Generated for RDP Negotiation Failure messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :failure_code: The failure code sent by the server.

.. zeek:id:: rdp_negotiation_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated for RDP Negotiation Response messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol selected by the server.

.. zeek:id:: rdp_server_certificate

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cert_type: :zeek:type:`count`, permanently_issued: :zeek:type:`bool`)

   Generated for a server certificate section.  If multiple X.509 
   certificates are included in chain, this event will still
   only be generated a single time.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cert_type: Indicates the type of certificate.
   

   :permanently_issued: Value will be true is the certificate(s) is permanent on the server.

.. zeek:id:: rdp_server_security

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, encryption_method: :zeek:type:`count`, encryption_level: :zeek:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :encryption_method: The 32-bit integer representing the encryption method used in the connection.
   

   :encryption_level: The 32-bit integer representing the encryption level used in the connection.


