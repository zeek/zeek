:tocdepth: 3

base/bif/plugins/Zeek_SSL.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=================================================================================== =====================================================================================
:zeek:id:`ssl_alert`: :zeek:type:`event`                                            Generated for SSL/TLS alert records.
:zeek:id:`ssl_change_cipher_spec`: :zeek:type:`event`                               This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
                                                                                    before encryption begins.
:zeek:id:`ssl_client_hello`: :zeek:type:`event`                                     Generated for an SSL/TLS client's initial *hello* message.
:zeek:id:`ssl_dh_client_params`: :zeek:type:`event`                                 Generated if a client uses a DH-anon or DHE cipher suite.
:zeek:id:`ssl_dh_server_params`: :zeek:type:`event`                                 Generated if a server uses a DH-anon or DHE cipher suite.
:zeek:id:`ssl_ecdh_client_params`: :zeek:type:`event`                               Generated if a client uses an ECDH-anon or ECDHE cipher suite.
:zeek:id:`ssl_ecdh_server_params`: :zeek:type:`event`                               Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
                                                                                    This event contains the named curve name and the server ECDH parameters contained
                                                                                    in the ServerKeyExchange message as defined in :rfc:`4492`.
:zeek:id:`ssl_encrypted_data`: :zeek:type:`event`                                   Generated for SSL/TLS messages that are sent after session encryption
                                                                                    started.
:zeek:id:`ssl_established`: :zeek:type:`event`                                      Generated at the end of an SSL/TLS handshake.
:zeek:id:`ssl_extension`: :zeek:type:`event`                                        Generated for SSL/TLS extensions seen in an initial handshake.
:zeek:id:`ssl_extension_application_layer_protocol_negotiation`: :zeek:type:`event` Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
:zeek:id:`ssl_extension_ec_point_formats`: :zeek:type:`event`                       Generated for an SSL/TLS Supported Point Formats extension.
:zeek:id:`ssl_extension_elliptic_curves`: :zeek:type:`event`                        Generated for an SSL/TLS Elliptic Curves extension.
:zeek:id:`ssl_extension_key_share`: :zeek:type:`event`                              Generated for a Key Share extension.
:zeek:id:`ssl_extension_pre_shared_key_client_hello`: :zeek:type:`event`            Generated for the pre-shared key extension as it is sent in the TLS 1.3 client hello.
:zeek:id:`ssl_extension_pre_shared_key_server_hello`: :zeek:type:`event`            Generated for the pre-shared key extension as it is sent in the TLS 1.3 server hello.
:zeek:id:`ssl_extension_psk_key_exchange_modes`: :zeek:type:`event`                 Generated for an TLS Pre-Shared Key Exchange Modes extension.
:zeek:id:`ssl_extension_server_name`: :zeek:type:`event`                            Generated for an SSL/TLS Server Name extension.
:zeek:id:`ssl_extension_signature_algorithm`: :zeek:type:`event`                    Generated for an Signature Algorithms extension.
:zeek:id:`ssl_extension_signed_certificate_timestamp`: :zeek:type:`event`           Generated for the signed_certificate_timestamp TLS extension as defined in
                                                                                    :rfc:`6962`.
:zeek:id:`ssl_extension_supported_versions`: :zeek:type:`event`                     Generated for an TLS Supported Versions extension.
:zeek:id:`ssl_handshake_message`: :zeek:type:`event`                                This event is raised for each unencrypted SSL/TLS handshake message.
:zeek:id:`ssl_heartbeat`: :zeek:type:`event`                                        Generated for SSL/TLS heartbeat messages that are sent before session
                                                                                    encryption starts.
:zeek:id:`ssl_plaintext_data`: :zeek:type:`event`                                   Generated for SSL/TLS messages that are sent before full session encryption
                                                                                    starts.
:zeek:id:`ssl_rsa_client_pms`: :zeek:type:`event`                                   Generated if a client uses RSA key exchange.
:zeek:id:`ssl_server_hello`: :zeek:type:`event`                                     Generated for an SSL/TLS server's initial *hello* message.
:zeek:id:`ssl_server_signature`: :zeek:type:`event`                                 Generated if a server uses a non-anonymous DHE or ECDHE cipher suite.
:zeek:id:`ssl_session_ticket_handshake`: :zeek:type:`event`                         Generated for SSL/TLS handshake messages that are a part of the
                                                                                    stateless-server session resumption mechanism.
:zeek:id:`ssl_stapled_ocsp`: :zeek:type:`event`                                     This event contains the OCSP response contained in a Certificate Status Request
                                                                                    message, when the client requested OCSP stapling and the server supports it.
=================================================================================== =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: ssl_alert

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, level: :zeek:type:`count`, desc: :zeek:type:`count`)

   Generated for SSL/TLS alert records. SSL/TLS sessions start with an
   unencrypted handshake, and Zeek extracts as much information out of that as
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
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake

.. zeek:id:: ssl_change_cipher_spec

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
   before encryption begins. Traffic will be encrypted following this message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_handshake_message

.. zeek:id:: ssl_client_hello

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, record_version: :zeek:type:`count`, possible_ts: :zeek:type:`time`, client_random: :zeek:type:`string`, session_id: :zeek:type:`string`, ciphers: :zeek:type:`index_vec`, comp_methods: :zeek:type:`index_vec`)

   Generated for an SSL/TLS client's initial *hello* message.  SSL/TLS sessions
   start with an unencrypted handshake, and Zeek extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the client's message.  The
            values are standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the client. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care.
   

   :session_id: The session ID sent by the client (if any).
   

   :client_random: The random value sent by the client. For version 2 connections,
   		  the client challenge is returned.
   

   :ciphers: The list of ciphers the client offered to use. The values are
            standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::cipher_desc` table maps them to descriptive names.
   

   :comp_methods: The list of compression methods that the client offered to use.
                 This value is not sent in TLSv1.3 or SSLv2.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_handshake_message
      ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. zeek:id:: ssl_dh_client_params

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, Yc: :zeek:type:`string`)

   Generated if a client uses a DH-anon or DHE cipher suite. This event contains
   the client DH parameters contained in the ClientKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :Yc: The client's DH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_ecdh_server_params ssl_ecdh_client_params ssl_rsa_client_pms

.. zeek:id:: ssl_dh_server_params

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, p: :zeek:type:`string`, q: :zeek:type:`string`, Ys: :zeek:type:`string`)

   Generated if a server uses a DH-anon or DHE cipher suite. This event contains
   the server DH parameters, contained in the ServerKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :p: The DH prime modulus.
   

   :q: The DH generator.
   

   :Ys: The server's DH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. zeek:id:: ssl_ecdh_client_params

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, point: :zeek:type:`string`)

   Generated if a client uses an ECDH-anon or ECDHE cipher suite. This event
   contains the client ECDH public value contained in the ClientKeyExchange
   message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :point: The client's ECDH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_rsa_client_pms

.. zeek:id:: ssl_ecdh_server_params

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, curve: :zeek:type:`count`, point: :zeek:type:`string`)

   Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
   This event contains the named curve name and the server ECDH parameters contained
   in the ServerKeyExchange message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :curve: The curve parameters.
   

   :point: The server's ECDH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_client_params ssl_rsa_client_pms

.. zeek:id:: ssl_encrypted_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, record_version: :zeek:type:`count`, content_type: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for SSL/TLS messages that are sent after session encryption
   started.
   
   Note that :zeek:id:`SSL::disable_analyzer_after_detection` has to be changed
   from its default to false for this event to be generated.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. zeek:id:: ssl_established

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated at the end of an SSL/TLS handshake. SSL/TLS sessions start with
   an unencrypted handshake, and Zeek extracts as much information out of that
   as it can. This event signals the time when an SSL/TLS has finished the
   handshake and its endpoints consider it as fully established. Typically,
   everything from now on will be encrypted.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   
   .. zeek:see:: ssl_alert ssl_client_hello  ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate

.. zeek:id:: ssl_extension

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, code: :zeek:type:`count`, val: :zeek:type:`string`)

   Generated for SSL/TLS extensions seen in an initial handshake.  SSL/TLS
   sessions start with an unencrypted handshake, and Zeek extracts as much
   information out of that as it can. This event provides access to any
   extensions either side sends as part of an extended *hello* message.
   
   Note that Zeek offers more specialized events for a few extensions.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :code: The numerical code of the extension.  The values are standardized as
         part of the SSL/TLS protocol. The :zeek:id:`SSL::extensions` table maps
         them to descriptive names.
   

   :val: The raw extension value that was sent in the message.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension_ec_point_formats
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_application_layer_protocol_negotiation

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, protocols: :zeek:type:`string_vec`)

   Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
   This TLS extension is defined in draft-ietf-tls-applayerprotoneg and sent in
   the initial handshake. It contains the list of client supported application
   protocols by the client or the server, respectively.
   
   At the moment it is mostly used to negotiate the use of SPDY / HTTP2.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :protocols: List of supported application layer protocols.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_ec_point_formats

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, point_formats: :zeek:type:`index_vec`)

   Generated for an SSL/TLS Supported Point Formats extension. This TLS extension
   is defined in :rfc:`4492` and sent by the client and/or server in the initial
   handshake. It gives the list of elliptic curve point formats supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :point_formats: List of supported point formats.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_elliptic_curves

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, curves: :zeek:type:`index_vec`)

   Generated for an SSL/TLS Elliptic Curves extension. This TLS extension is
   defined in :rfc:`4492` and sent by the client in the initial handshake. It
   gives the list of elliptic curves supported by the client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :curves: List of supported elliptic curves.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_ec_point_formats ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm
      ssl_extension_key_share ssl_rsa_client_pms ssl_server_signature
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_key_share

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, curves: :zeek:type:`index_vec`)

   Generated for a Key Share extension. This TLS extension is defined in TLS1.3-draft16
   and sent by the client and the server in the initial handshake. It gives the list of
   named groups supported by the client and chosen by the server.
   

   :c: The connection.
   

   :is_orig: True if event is raised for the originator side of the connection.
   

   :curves: List of supported/chosen named groups.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_pre_shared_key_client_hello

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, identities: :zeek:type:`psk_identity_vec`, binders: :zeek:type:`string_vec`)

   Generated for the pre-shared key extension as it is sent in the TLS 1.3 client hello.
   
   The extension lists the identities the client is willing to negotiate with the server;
   they can either be pre-shared or be based on previous handshakes.
   

   :c: The connection.
   

   :is_orig: True if event is raised for the originator side of the connection
   

   :identities: A list of the identities the client is willing to negotiate with the server.
   

   :binders: A series of HMAC values; for computation, see the TLS 1.3 RFC.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature ssl_extension_pre_shared_key_server_hello

.. zeek:id:: ssl_extension_pre_shared_key_server_hello

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, selected_identity: :zeek:type:`count`)

   Generated for the pre-shared key extension as it is sent in the TLS 1.3 server hello.
   

   :c: The connection.
   

   :is_orig: True if event is raised for the originator side of the connection
   

   :selected_identity: The identity the server chose as a 0-based index into the identities
                      the client sent.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_psk_key_exchange_modes

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, modes: :zeek:type:`index_vec`)

   Generated for an TLS Pre-Shared Key Exchange Modes extension. This TLS extension is defined
   in the TLS 1.3 rfc and sent by the client in the initial handshake. It contains the
   list of Pre-Shared Key Exchange Modes that it supports.

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported Pre-Shared Key Exchange Modes.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_supported_versions ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_server_name

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, names: :zeek:type:`string_vec`)

   Generated for an SSL/TLS Server Name extension. This SSL/TLS extension is
   defined in :rfc:`3546` and sent by the client in the initial handshake. It
   contains the name of the server it is contacting. This information can be
   used by the server to choose the correct certificate for the host the client
   wants to contact.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :names: A list of server names (DNS hostnames).
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_signature_algorithm

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, signature_algorithms: :zeek:type:`signature_and_hashalgorithm_vec`)

   Generated for an Signature Algorithms extension. This TLS extension
   is defined in :rfc:`5246` and sent by the client in the initial
   handshake. It gives the list of signature and hash algorithms supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :signature_algorithms: List of supported signature and hash algorithm pairs.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_signed_certificate_timestamp

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, logid: :zeek:type:`string`, timestamp: :zeek:type:`count`, signature_and_hashalgorithm: :zeek:type:`SSL::SignatureAndHashAlgorithm`, signature: :zeek:type:`string`)

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
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_application_layer_protocol_negotiation
      x509_ocsp_ext_signed_certificate_timestamp sct_verify
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_extension_supported_versions

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, versions: :zeek:type:`index_vec`)

   Generated for an TLS Supported Versions extension. This TLS extension
   is defined in the TLS 1.3 rfc and sent by the client in the initial handshake.
   It contains the TLS versions that it supports. This informaion can be used by
   the server to choose the best TLS version o use.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported TLS versions.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_handshake_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_type: :zeek:type:`count`, length: :zeek:type:`count`)

   This event is raised for each unencrypted SSL/TLS handshake message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :msg_type: Type of the handshake message that was seen.
   

   :length: Length of the handshake message that was seen.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_change_cipher_spec

.. zeek:id:: ssl_heartbeat

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, length: :zeek:type:`count`, heartbeat_type: :zeek:type:`count`, payload_length: :zeek:type:`count`, payload: :zeek:type:`string`)

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
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_encrypted_data

.. zeek:id:: ssl_plaintext_data

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, record_version: :zeek:type:`count`, content_type: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for SSL/TLS messages that are sent before full session encryption
   starts. Note that "full encryption" is a bit fuzzy, especially for TLSv1.3;
   here this event will be raised for early packets that are already using
   pre-encryption.  # This event is also used by Zeek internally to determine if
   the connection has been completely setup. This is necessary as TLS 1.3 does
   not have CCS anymore.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. zeek:id:: ssl_rsa_client_pms

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, pms: :zeek:type:`string`)

   Generated if a client uses RSA key exchange. This event contains the client
   encrypted pre-master secret which is encrypted using the public key of the
   server's certificate as defined in :rfc:`5246`.
   

   :c: The connection.
   

   :pms: The encrypted pre-master secret.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. zeek:id:: ssl_server_hello

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, record_version: :zeek:type:`count`, possible_ts: :zeek:type:`time`, server_random: :zeek:type:`string`, session_id: :zeek:type:`string`, cipher: :zeek:type:`count`, comp_method: :zeek:type:`count`)

   Generated for an SSL/TLS server's initial *hello* message. SSL/TLS sessions
   start with an unencrypted handshake, and Zeek extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the server's message.
            The values are standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the server. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care. This value
                is meaningless in SSLv2 and TLSv1.3.
   

   :session_id: The session ID as sent back by the server (if any). This value is not
               sent in TLSv1.3.
   

   :server_random: The random value sent by the server. For version 2 connections,
   		  the connection-id is returned. Note - the full 32 bytes are included in
   		  server_random. This means that the 4 bytes present in possible_ts are repeated;
   		  if you do not want this behavior ignore the first 4 bytes.
   

   :cipher: The cipher chosen by the server.  The values are standardized as part
           of the SSL/TLS protocol. The :zeek:id:`SSL::cipher_desc` table maps
           them to descriptive names.
   

   :comp_method: The compression method chosen by the client. The values are
                standardized as part of the SSL/TLS protocol. This value is not
                sent in TLSv1.3 or SSLv2.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_extension
      ssl_session_ticket_handshake x509_certificate
      ssl_dh_server_params ssl_handshake_message ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. zeek:id:: ssl_server_signature

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, signature_and_hashalgorithm: :zeek:type:`SSL::SignatureAndHashAlgorithm`, signature: :zeek:type:`string`)

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
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_rsa_client_pms
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. zeek:id:: ssl_session_ticket_handshake

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ticket_lifetime_hint: :zeek:type:`count`, ticket: :zeek:type:`string`)

   Generated for SSL/TLS handshake messages that are a part of the
   stateless-server session resumption mechanism. SSL/TLS sessions start with
   an unencrypted handshake, and Zeek extracts as much information out of that
   as it can. This event is raised when an SSL/TLS server passes a session
   ticket to the client that can later be used for resuming the session. The
   mechanism is described in :rfc:`4507`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :ticket_lifetime_hint: A hint from the server about how long the ticket
                         should be stored by the client.
   

   :ticket: The raw ticket data.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert

.. zeek:id:: ssl_stapled_ocsp

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, response: :zeek:type:`string`)

   This event contains the OCSP response contained in a Certificate Status Request
   message, when the client requested OCSP stapling and the server supports it.
   See description in :rfc:`6066`.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :response: OCSP data.


