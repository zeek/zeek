:tocdepth: 3

base/bif/plugins/Bro_SSL.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================================================= =================================================================================
:bro:id:`ssl_alert`: :bro:type:`event`                                            Generated for SSL/TLS alert records.
:bro:id:`ssl_change_cipher_spec`: :bro:type:`event`                               This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
                                                                                  before encryption begins.
:bro:id:`ssl_client_hello`: :bro:type:`event`                                     Generated for an SSL/TLS client's initial *hello* message.
:bro:id:`ssl_dh_client_params`: :bro:type:`event`                                 Generated if a client uses a DH-anon or DHE cipher suite.
:bro:id:`ssl_dh_server_params`: :bro:type:`event`                                 Generated if a server uses a DH-anon or DHE cipher suite.
:bro:id:`ssl_ecdh_client_params`: :bro:type:`event`                               Generated if a client uses an ECDH-anon or ECDHE cipher suite.
:bro:id:`ssl_ecdh_server_params`: :bro:type:`event`                               Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
                                                                                  This event contains the named curve name and the server ECDH parameters contained
                                                                                  in the ServerKeyExchange message as defined in :rfc:`4492`.
:bro:id:`ssl_encrypted_data`: :bro:type:`event`                                   Generated for SSL/TLS messages that are sent after session encryption
                                                                                  started.
:bro:id:`ssl_established`: :bro:type:`event`                                      Generated at the end of an SSL/TLS handshake.
:bro:id:`ssl_extension`: :bro:type:`event`                                        Generated for SSL/TLS extensions seen in an initial handshake.
:bro:id:`ssl_extension_application_layer_protocol_negotiation`: :bro:type:`event` Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
:bro:id:`ssl_extension_ec_point_formats`: :bro:type:`event`                       Generated for an SSL/TLS Supported Point Formats extension.
:bro:id:`ssl_extension_elliptic_curves`: :bro:type:`event`                        Generated for an SSL/TLS Elliptic Curves extension.
:bro:id:`ssl_extension_key_share`: :bro:type:`event`                              Generated for a Key Share extension.
:bro:id:`ssl_extension_psk_key_exchange_modes`: :bro:type:`event`                 Generated for an TLS Pre-Shared Key Exchange Modes extension.
:bro:id:`ssl_extension_server_name`: :bro:type:`event`                            Generated for an SSL/TLS Server Name extension.
:bro:id:`ssl_extension_signature_algorithm`: :bro:type:`event`                    Generated for an Signature Algorithms extension.
:bro:id:`ssl_extension_signed_certificate_timestamp`: :bro:type:`event`           Generated for the signed_certificate_timestamp TLS extension as defined in
                                                                                  :rfc:`6962`.
:bro:id:`ssl_extension_supported_versions`: :bro:type:`event`                     Generated for an TLS Supported Versions extension.
:bro:id:`ssl_handshake_message`: :bro:type:`event`                                This event is raised for each unencrypted SSL/TLS handshake message.
:bro:id:`ssl_heartbeat`: :bro:type:`event`                                        Generated for SSL/TLS heartbeat messages that are sent before session
                                                                                  encryption starts.
:bro:id:`ssl_plaintext_data`: :bro:type:`event`                                   Generated for SSL/TLS messages that are sent before full session encryption
                                                                                  starts.
:bro:id:`ssl_rsa_client_pms`: :bro:type:`event`                                   Generated if a client uses RSA key exchange.
:bro:id:`ssl_server_curve`: :bro:type:`event` :bro:attr:`&deprecated`             Generated if a named curve is chosen by the server for an SSL/TLS connection.
:bro:id:`ssl_server_hello`: :bro:type:`event`                                     Generated for an SSL/TLS server's initial *hello* message.
:bro:id:`ssl_server_signature`: :bro:type:`event`                                 Generated if a server uses a non-anonymous DHE or ECDHE cipher suite.
:bro:id:`ssl_session_ticket_handshake`: :bro:type:`event`                         Generated for SSL/TLS handshake messages that are a part of the
                                                                                  stateless-server session resumption mechanism.
:bro:id:`ssl_stapled_ocsp`: :bro:type:`event`                                     This event contains the OCSP response contained in a Certificate Status Request
                                                                                  message, when the client requested OCSP stapling and the server supports it.
================================================================================= =================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ssl_alert

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, level: :bro:type:`count`, desc: :bro:type:`count`)

   Generated for SSL/TLS alert records. SSL/TLS sessions start with an
   unencrypted handshake, and Bro extracts as much information out of that as
   it can. If during that handshake, an endpoint encounters a fatal error, it
   sends an *alert* record, that in turn triggers this event. After an *alert*,
   any endpoint may close the connection immediately.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :level: The severity level, as sent in the *alert*. The values are defined as
          part of the SSL/TLS protocol.
   

   :desc: A numerical value identifying the cause of the *alert*. The values are
         defined as part of the SSL/TLS protocol.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake

.. bro:id:: ssl_change_cipher_spec

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
   before encryption begins. Traffic will be encrypted following this message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_handshake_message

.. bro:id:: ssl_client_hello

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, record_version: :bro:type:`count`, possible_ts: :bro:type:`time`, client_random: :bro:type:`string`, session_id: :bro:type:`string`, ciphers: :bro:type:`index_vec`, comp_methods: :bro:type:`index_vec`)

   Generated for an SSL/TLS client's initial *hello* message.  SSL/TLS sessions
   start with an unencrypted handshake, and Bro extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the client's message.  The
            values are standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the client. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care.
   

   :session_id: The session ID sent by the client (if any).
   

   :client_random: The random value sent by the client. For version 2 connections,
   		  the client challenge is returned.
   

   :ciphers: The list of ciphers the client offered to use. The values are
            standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::cipher_desc` table maps them to descriptive names.
   

   :comp_methods: The list of compression methods that the client offered to use.
                 This value is not sent in TLSv1.3 or SSLv2.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_handshake_message
      ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_dh_client_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, Yc: :bro:type:`string`)

   Generated if a client uses a DH-anon or DHE cipher suite. This event contains
   the client DH parameters contained in the ClientKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :Yc: The client's DH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_ecdh_server_params ssl_ecdh_client_params ssl_rsa_client_pms

.. bro:id:: ssl_dh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, q: :bro:type:`string`, Ys: :bro:type:`string`)

   Generated if a server uses a DH-anon or DHE cipher suite. This event contains
   the server DH parameters, contained in the ServerKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :p: The DH prime modulus.
   

   :q: The DH generator.
   

   :Ys: The server's DH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_ecdh_client_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, point: :bro:type:`string`)

   Generated if a client uses an ECDH-anon or ECDHE cipher suite. This event
   contains the client ECDH public value contained in the ClientKeyExchange
   message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :point: The client's ECDH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_rsa_client_pms

.. bro:id:: ssl_ecdh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, curve: :bro:type:`count`, point: :bro:type:`string`)

   Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
   This event contains the named curve name and the server ECDH parameters contained
   in the ServerKeyExchange message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :curve: The curve parameters.
   

   :point: The server's ECDH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_client_params ssl_rsa_client_pms

.. bro:id:: ssl_encrypted_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, record_version: :bro:type:`count`, content_type: :bro:type:`count`, length: :bro:type:`count`)

   Generated for SSL/TLS messages that are sent after session encryption
   started.
   
   Note that :bro:id:`SSL::disable_analyzer_after_detection` has to be changed
   from its default to false for this event to be generated.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. bro:id:: ssl_established

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated at the end of an SSL/TLS handshake. SSL/TLS sessions start with
   an unencrypted handshake, and Bro extracts as much information out of that
   as it can. This event signals the time when an SSL/TLS has finished the
   handshake and its endpoints consider it as fully established. Typically,
   everything from now on will be encrypted.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   
   .. bro:see:: ssl_alert ssl_client_hello  ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate

.. bro:id:: ssl_extension

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, code: :bro:type:`count`, val: :bro:type:`string`)

   Generated for SSL/TLS extensions seen in an initial handshake.  SSL/TLS
   sessions start with an unencrypted handshake, and Bro extracts as much
   information out of that as it can. This event provides access to any
   extensions either side sends as part of an extended *hello* message.
   
   Note that Bro offers more specialized events for a few extensions.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :code: The numerical code of the extension.  The values are standardized as
         part of the SSL/TLS protocol. The :bro:id:`SSL::extensions` table maps
         them to descriptive names.
   

   :val: The raw extension value that was sent in the message.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension_ec_point_formats
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions

.. bro:id:: ssl_extension_application_layer_protocol_negotiation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, protocols: :bro:type:`string_vec`)

   Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
   This TLS extension is defined in draft-ietf-tls-applayerprotoneg and sent in
   the initial handshake. It contains the list of client supported application
   protocols by the client or the server, respectively.
   
   At the moment it is mostly used to negotiate the use of SPDY / HTTP2.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :protocols: List of supported application layer protocols.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_ec_point_formats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, point_formats: :bro:type:`index_vec`)

   Generated for an SSL/TLS Supported Point Formats extension. This TLS extension
   is defined in :rfc:`4492` and sent by the client and/or server in the initial
   handshake. It gives the list of elliptic curve point formats supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :point_formats: List of supported point formats.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_signature_algorithm
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_extension_elliptic_curves

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, curves: :bro:type:`index_vec`)

   Generated for an SSL/TLS Elliptic Curves extension. This TLS extension is
   defined in :rfc:`4492` and sent by the client in the initial handshake. It
   gives the list of elliptic curves supported by the client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :curves: List of supported elliptic curves.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_ec_point_formats ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_signature_algorithm
      ssl_extension_key_share ssl_rsa_client_pms ssl_server_signature
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_extension_key_share

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, curves: :bro:type:`index_vec`)

   Generated for a Key Share extension. This TLS extension is defined in TLS1.3-draft16
   and sent by the client and the server in the initial handshake. It gives the list of
   named groups supported by the client and chosen by the server.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :curves: List of supported/chosen named groups.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_extension_psk_key_exchange_modes

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, modes: :bro:type:`index_vec`)

   Generated for an TLS Pre-Shared Key Exchange Modes extension. This TLS extension is defined
   in the TLS 1.3 rfc and sent by the client in the initial handshake. It contains the
   list of Pre-Shared Key Exchange Modes that it supports.

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported Pre-Shared Key Exchange Modes.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_supported_versions ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_server_name

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, names: :bro:type:`string_vec`)

   Generated for an SSL/TLS Server Name extension. This SSL/TLS extension is
   defined in :rfc:`3546` and sent by the client in the initial handshake. It
   contains the name of the server it is contacting. This information can be
   used by the server to choose the correct certificate for the host the client
   wants to contact.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :names: A list of server names (DNS hostnames).
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_signature_algorithm

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, signature_algorithms: :bro:type:`signature_and_hashalgorithm_vec`)

   Generated for an Signature Algorithms extension. This TLS extension
   is defined in :rfc:`5246` and sent by the client in the initial
   handshake. It gives the list of signature and hash algorithms supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :signature_algorithms: List of supported signature and hash algorithm pairs.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_extension_signed_certificate_timestamp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, version: :bro:type:`count`, logid: :bro:type:`string`, timestamp: :bro:type:`count`, signature_and_hashalgorithm: :bro:type:`SSL::SignatureAndHashAlgorithm`, signature: :bro:type:`string`)

   Generated for the signed_certificate_timestamp TLS extension as defined in
   :rfc:`6962`. The extension is used to transmit signed proofs that are
   used for Certificate Transparency.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :version: the version of the protocol to which the SCT conforms. Always
            should be 0 (representing version 1)
   

   :logid: 32 bit key id
   

   :timestamp: the NTP Time when the entry was logged measured since
              the epoch, ignoring leap seconds, in milliseconds.
   

   :signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct
   

   :signature: signature part of the digitally_signed struct
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_application_layer_protocol_negotiation
      x509_ocsp_ext_signed_certificate_timestamp sct_verify

.. bro:id:: ssl_extension_supported_versions

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, versions: :bro:type:`index_vec`)

   Generated for an TLS Supported Versions extension. This TLS extension
   is defined in the TLS 1.3 rfc and sent by the client in the initial handshake.
   It contains the TLS versions that it supports. This informaion can be used by
   the server to choose the best TLS version o use.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported TLS versions.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_handshake_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg_type: :bro:type:`count`, length: :bro:type:`count`)

   This event is raised for each unencrypted SSL/TLS handshake message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :msg_type: Type of the handshake message that was seen.
   

   :length: Length of the handshake message that was seen.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_change_cipher_spec

.. bro:id:: ssl_heartbeat

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, length: :bro:type:`count`, heartbeat_type: :bro:type:`count`, payload_length: :bro:type:`count`, payload: :bro:type:`string`)

   Generated for SSL/TLS heartbeat messages that are sent before session
   encryption starts. Generally heartbeat messages should rarely be seen in
   normal TLS traffic. Heartbeats are described in :rfc:`6520`.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :length: length of the entire heartbeat message.
   

   :heartbeat_type: type of the heartbeat message. Per RFC, 1 = request, 2 = response.
   

   :payload_length: length of the payload of the heartbeat message, according to
                   packet field.
   

   :payload: payload contained in the heartbeat message. Size can differ from
            payload_length, if payload_length and actual packet length disagree.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_encrypted_data

.. bro:id:: ssl_plaintext_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, record_version: :bro:type:`count`, content_type: :bro:type:`count`, length: :bro:type:`count`)

   Generated for SSL/TLS messages that are sent before full session encryption
   starts. Note that "full encryption" is a bit fuzzy, especially for TLSv1.3;
   here this event will be raised for early packets that are already using
   pre-encryption.  # This event is also used by Bro internally to determine if
   the connection has been completely setup. This is necessary as TLS 1.3 does
   not have CCS anymore.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. bro:id:: ssl_rsa_client_pms

   :Type: :bro:type:`event` (c: :bro:type:`connection`, pms: :bro:type:`string`)

   Generated if a client uses RSA key exchange. This event contains the client
   encrypted pre-master secret which is encrypted using the public key of the
   server's certificate as defined in :rfc:`5246`.
   

   :c: The connection.
   

   :pms: The encrypted pre-master secret.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_server_curve

   :Type: :bro:type:`event` (c: :bro:type:`connection`, curve: :bro:type:`count`)
   :Attributes: :bro:attr:`&deprecated`

   Generated if a named curve is chosen by the server for an SSL/TLS connection.
   The curve is sent by the server in the ServerKeyExchange message as defined
   in :rfc:`4492`, in case an ECDH or ECDHE cipher suite is chosen.
   

   :c: The connection.
   

   :curve: The curve.
   
   .. note:: This event is deprecated and superseded by the ssl_ecdh_server_params
             event. This event will be removed in a future version of Bro.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_server_hello

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, record_version: :bro:type:`count`, possible_ts: :bro:type:`time`, server_random: :bro:type:`string`, session_id: :bro:type:`string`, cipher: :bro:type:`count`, comp_method: :bro:type:`count`)

   Generated for an SSL/TLS server's initial *hello* message. SSL/TLS sessions
   start with an unencrypted handshake, and Bro extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the server's message.
            The values are standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the server. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care. This value
                is not sent in TLSv1.3.
   

   :session_id: The session ID as sent back by the server (if any). This value is not
               sent in TLSv1.3.
   

   :server_random: The random value sent by the server. For version 2 connections,
   		  the connection-id is returned.
   

   :cipher: The cipher chosen by the server.  The values are standardized as part
           of the SSL/TLS protocol. The :bro:id:`SSL::cipher_desc` table maps
           them to descriptive names.
   

   :comp_method: The compression method chosen by the client. The values are
                standardized as part of the SSL/TLS protocol. This value is not
                sent in TLSv1.3 or SSLv2.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_extension
      ssl_session_ticket_handshake x509_certificate ssl_server_curve
      ssl_dh_server_params ssl_handshake_message ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_server_signature

   :Type: :bro:type:`event` (c: :bro:type:`connection`, signature_and_hashalgorithm: :bro:type:`SSL::SignatureAndHashAlgorithm`, signature: :bro:type:`string`)

   Generated if a server uses a non-anonymous DHE or ECDHE cipher suite. This event
   contains the server signature over the key exchange parameters contained in
   the ServerKeyExchange message as defined in :rfc:`4492` and :rfc:`5246`.
   

   :c: The connection.
   

   :signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct. This field is only present
                                starting with TLSv1.2 and DTLSv1.2. Earlier versions
                                used a hardcoded hash algorithm. For protocol versions
                                below D(TLS)v1.2 this field is filled with an dummy
                                value of 256.
   

   :signature: Signature part of the digitally_signed struct. The private key
              corresponding to the certified public key in the server's certificate
              message is used for signing.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_rsa_client_pms
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_session_ticket_handshake

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ticket_lifetime_hint: :bro:type:`count`, ticket: :bro:type:`string`)

   Generated for SSL/TLS handshake messages that are a part of the
   stateless-server session resumption mechanism. SSL/TLS sessions start with
   an unencrypted handshake, and Bro extracts as much information out of that
   as it can. This event is raised when an SSL/TLS server passes a session
   ticket to the client that can later be used for resuming the session. The
   mechanism is described in :rfc:`4507`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :ticket_lifetime_hint: A hint from the server about how long the ticket
                         should be stored by the client.
   

   :ticket: The raw ticket data.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert

.. bro:id:: ssl_stapled_ocsp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, response: :bro:type:`string`)

   This event contains the OCSP response contained in a Certificate Status Request
   message, when the client requested OCSP stapling and the server supports it.
   See description in :rfc:`6066`.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :response: OCSP data.


