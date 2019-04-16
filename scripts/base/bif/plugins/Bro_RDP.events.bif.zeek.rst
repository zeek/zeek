:tocdepth: 3

base/bif/plugins/Bro_RDP.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ================================================
:bro:id:`rdp_begin_encryption`: :bro:type:`event`           Generated when an RDP session becomes encrypted.
:bro:id:`rdp_client_core_data`: :bro:type:`event`           Generated for MCS client requests.
:bro:id:`rdp_connect_request`: :bro:type:`event`            Generated for X.224 client requests.
:bro:id:`rdp_gcc_server_create_response`: :bro:type:`event` Generated for MCS server responses.
:bro:id:`rdp_negotiation_failure`: :bro:type:`event`        Generated for RDP Negotiation Failure messages.
:bro:id:`rdp_negotiation_response`: :bro:type:`event`       Generated for RDP Negotiation Response messages.
:bro:id:`rdp_server_certificate`: :bro:type:`event`         Generated for a server certificate section.
:bro:id:`rdp_server_security`: :bro:type:`event`            Generated for MCS server responses.
=========================================================== ================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: rdp_begin_encryption

   :Type: :bro:type:`event` (c: :bro:type:`connection`, security_protocol: :bro:type:`count`)

   Generated when an RDP session becomes encrypted.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol being used for the session.

.. bro:id:: rdp_client_core_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, data: :bro:type:`RDP::ClientCoreData`)

   Generated for MCS client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :data: The data contained in the client core data structure.

.. bro:id:: rdp_connect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cookie: :bro:type:`string`)

   Generated for X.224 client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cookie: The cookie included in the request.

.. bro:id:: rdp_gcc_server_create_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: The 8-bit integer representing the GCC Conference Create Response result.

.. bro:id:: rdp_negotiation_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, failure_code: :bro:type:`count`)

   Generated for RDP Negotiation Failure messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :failure_code: The failure code sent by the server.

.. bro:id:: rdp_negotiation_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, security_protocol: :bro:type:`count`)

   Generated for RDP Negotiation Response messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol selected by the server.

.. bro:id:: rdp_server_certificate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cert_type: :bro:type:`count`, permanently_issued: :bro:type:`bool`)

   Generated for a server certificate section.  If multiple X.509 
   certificates are included in chain, this event will still
   only be generated a single time.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cert_type: Indicates the type of certificate.
   

   :permanently_issued: Value will be true is the certificate(s) is permanent on the server.

.. bro:id:: rdp_server_security

   :Type: :bro:type:`event` (c: :bro:type:`connection`, encryption_method: :bro:type:`count`, encryption_level: :bro:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :encryption_method: The 32-bit integer representing the encryption method used in the connection.
   

   :encryption_level: The 32-bit integer representing the encryption level used in the connection.


