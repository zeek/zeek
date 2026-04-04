:tocdepth: 3

base/protocols/ssl/main.zeek
============================
.. zeek:namespace:: SSL

Base SSL analysis script.  This script logs information about the SSL/TLS
handshaking and encryption establishment process.

:Namespace: SSL
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/ssl/consts.zeek </scripts/base/protocols/ssl/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ===============================================================
:zeek:id:`SSL::ct_logs`: :zeek:type:`table` :zeek:attr:`&redef`                         The Certificate Transparency log bundle.
:zeek:id:`SSL::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` If true, detach the SSL analyzer from the connection to prevent
                                                                                        continuing to process encrypted traffic.
:zeek:id:`SSL::max_ssl_history_length`: :zeek:type:`count` :zeek:attr:`&redef`          Maximum length of the ssl_history field to prevent unbounded
                                                                                        growth when the parser is running into unexpected situations.
======================================================================================= ===============================================================

Redefinable Options
###################
================================================================== ===========================
:zeek:id:`SSL::dtls_ports`: :zeek:type:`set` :zeek:attr:`&redef`   Ports for DTLS.
:zeek:id:`SSL::root_certs`: :zeek:type:`table` :zeek:attr:`&redef` The default root CA bundle.
:zeek:id:`SSL::ssl_ports`: :zeek:type:`set` :zeek:attr:`&redef`    Well-known ports for SSL.
================================================================== ===========================

Types
#####
============================================= ============================================================
:zeek:type:`SSL::CTInfo`: :zeek:type:`record` The record type which contains the field for the Certificate
                                              Transparency log bundle.
:zeek:type:`SSL::Info`: :zeek:type:`record`   The record type which contains the fields of the SSL log.
============================================= ============================================================

Redefinitions
#############
============================================ =============================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`SSL::LOG`
:zeek:type:`SSL::Info`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`SSL::Info`

                                               delay_tokens: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               ssl: :zeek:type:`SSL::Info` :zeek:attr:`&optional`
============================================ =============================================================================

Events
######
=========================================== =================================================
:zeek:id:`SSL::log_ssl`: :zeek:type:`event` Event that can be handled to access the SSL
                                            record as it is sent on to the logging framework.
=========================================== =================================================

Hooks
#####
============================================================ ====================================================================
:zeek:id:`SSL::finalize_ssl`: :zeek:type:`Conn::RemovalHook` SSL finalization hook.
:zeek:id:`SSL::log_policy`: :zeek:type:`Log::PolicyHook`
:zeek:id:`SSL::ssl_finishing`: :zeek:type:`hook`             Hook that can be used to perform actions right before the log record
                                                             is written.
============================================================ ====================================================================

Functions
#########
================================================== ====================================================================
:zeek:id:`SSL::delay_log`: :zeek:type:`function`   Delays an SSL record for a specific token: the record will not be
                                                   logged as long as the token exists or until 15 seconds elapses.
:zeek:id:`SSL::undelay_log`: :zeek:type:`function` Undelays an SSL record for a previously inserted token, allowing the
                                                   record to be logged.
================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSL::ct_logs
   :source-code: base/protocols/ssl/main.zeek 150 150

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`SSL::CTInfo`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/ssl/ct-list.zeek`

      << Value omitted due to ``@docs_omit_value`` annotation >>

   The Certificate Transparency log bundle. By default, the ct-list.zeek
   script sets this to the current list of known logs. Entries
   are indexed by (binary) log-id.

.. zeek:id:: SSL::disable_analyzer_after_detection
   :source-code: base/protocols/ssl/main.zeek 155 155

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``
   :Redefinition: from :doc:`/scripts/policy/protocols/ssl/decryption.zeek`

      ``=``::

         ``F``

   :Redefinition: from :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek`

      ``=``::

         ``F``


   If true, detach the SSL analyzer from the connection to prevent
   continuing to process encrypted traffic. Helps with performance
   (especially with large file transfers).

.. zeek:id:: SSL::max_ssl_history_length
   :source-code: base/protocols/ssl/main.zeek 159 159

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   Maximum length of the ssl_history field to prevent unbounded
   growth when the parser is running into unexpected situations.

Redefinable Options
###################
.. zeek:id:: SSL::dtls_ports
   :source-code: base/protocols/ssl/main.zeek 22 22

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            443/udp
         }


   Ports for DTLS.

.. zeek:id:: SSL::root_certs
   :source-code: base/protocols/ssl/main.zeek 130 130

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/ssl/mozilla-ca-list.zeek`

      << Value omitted due to ``@docs_omit_value`` annotation >>

   The default root CA bundle.  By default, the mozilla-ca-list.zeek
   script sets this to Mozilla's root CA list.

.. zeek:id:: SSL::ssl_ports
   :source-code: base/protocols/ssl/main.zeek 14 14

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            563/tcp,
            995/tcp,
            585/tcp,
            443/tcp,
            5223/tcp,
            992/tcp,
            636/tcp,
            990/tcp,
            993/tcp,
            989/tcp,
            614/tcp
         }


   Well-known ports for SSL.

Types
#####
.. zeek:type:: SSL::CTInfo
   :source-code: base/protocols/ssl/main.zeek 134 145

   :Type: :zeek:type:`record`


   .. zeek:field:: description :zeek:type:`string`

      Description of the Log


   .. zeek:field:: operator :zeek:type:`string`

      Operator of the Log


   .. zeek:field:: key :zeek:type:`string`

      Public key of the Log.


   .. zeek:field:: maximum_merge_delay :zeek:type:`count`

      Maximum merge delay of the Log


   .. zeek:field:: url :zeek:type:`string`

      URL of the Log


   The record type which contains the field for the Certificate
   Transparency log bundle.

.. zeek:type:: SSL::Info
   :source-code: base/protocols/ssl/main.zeek 27 126

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Time when the SSL connection was first detected.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: version_num :zeek:type:`count` :zeek:attr:`&optional`

      Numeric SSL/TLS version that the server chose.


   .. zeek:field:: version :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      SSL/TLS version that the server chose.


   .. zeek:field:: cipher :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      SSL/TLS cipher suite that the server chose.


   .. zeek:field:: curve :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Elliptic curve the server chose when using ECDH/ECDHE.


   .. zeek:field:: server_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the Server Name Indicator SSL/TLS extension.  It
      indicates the server name that the client was requesting.


   .. zeek:field:: session_id :zeek:type:`string` :zeek:attr:`&optional`

      Session ID offered by the client for session resumption.
      Not used for logging.


   .. zeek:field:: resumed :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate if the session was resumed reusing
      the key material exchanged in an earlier connection.


   .. zeek:field:: client_ticket_empty_session_seen :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate if we saw a non-empty session ticket being
      sent by the client using an empty session ID. This value
      is used to determine if a session is being resumed. It's
      not logged.


   .. zeek:field:: client_key_exchange_seen :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate if we saw a client key exchange message sent
      by the client. This value is used to determine if a session
      is being resumed. It's not logged.


   .. zeek:field:: client_psk_seen :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Track if the client sent a pre-shared-key extension.
      Used to determine if a TLS 1.3 session is being resumed.
      Not logged.


   .. zeek:field:: last_alert :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Last alert that was seen during the connection.


   .. zeek:field:: next_protocol :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Next protocol the server chose using the application layer
      next protocol extension, if present.


   .. zeek:field:: analyzer_id :zeek:type:`count` :zeek:attr:`&optional`

      The analyzer ID used for the analyzer instance attached
      to each connection.  It is not used for logging since it's a
      meaningless arbitrary number.


   .. zeek:field:: established :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate if this ssl session has been established
      successfully, or if it was aborted during the handshake.


   .. zeek:field:: logged :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate if this record already has been logged, to
      prevent duplicates.


   .. zeek:field:: hrr_seen :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Flag to indicate that we have seen a Hello Retry request message.
      Used internally for ssl_history logging


   .. zeek:field:: ssl_history :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      SSL history showing which types of packets we received in which order.
      Letters have the following meaning with client-sent letters being capitalized:

      A direction flip occurs when the client hello packet is not sent from the originator
      of a connection. This can, e.g., occur when DTLS is used in a connection that was
      set up using STUN.

      ======  ====================================================
      Letter  Meaning
      ======  ====================================================
      ^       direction flipped
      H       hello_request
      C       client_hello
      S       server_hello
      V       hello_verify_request
      T       NewSessionTicket
      X       certificate
      K       server_key_exchange
      R       certificate_request
      N       server_hello_done
      Y       certificate_verify
      G       client_key_exchange
      F       finished
      W       certificate_url
      U       certificate_status
      A       supplemental_data
      Z       unassigned_handshake_type
      I       change_cipher_spec
      B       heartbeat
      D       application_data
      E       end_of_early_data
      O       encrypted_extensions
      P       key_update
      M       message_hash
      J       hello_retry_request
      L       alert
      Q       unknown_content_type
      ======  ====================================================



   .. zeek:field:: delay_tokens :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`


   .. zeek:field:: cert_chain :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Chain of certificates offered by the server to validate its
      complete signing chain.


   .. zeek:field:: cert_chain_fps :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      An ordered vector of all certificate fingerprints for the
      certificates offered by the server.


   .. zeek:field:: client_cert_chain :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Chain of certificates offered by the client to validate its
      complete signing chain.


   .. zeek:field:: client_cert_chain_fps :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      An ordered vector of all certificate fingerprints for the
      certificates offered by the client.


   .. zeek:field:: subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Subject of the X.509 certificate offered by the server.


   .. zeek:field:: issuer :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Issuer of the signer of the X.509 certificate offered by the
      server.


   .. zeek:field:: client_subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Subject of the X.509 certificate offered by the client.


   .. zeek:field:: client_issuer :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Subject of the signer of the X.509 certificate offered by the
      client.


   .. zeek:field:: sni_matches_cert :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Set to true if the hostname sent in the SNI matches the certificate.
      Set to false if they do not match. Unset if the client did not send
      an SNI.


   .. zeek:field:: server_depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)

      Current number of certificates seen from either side. Used
      to create file handles.


   .. zeek:field:: client_depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/ssl/files.zeek` is loaded)


   .. zeek:field:: always_raise_x509_events :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/files/x509/disable-certificate-events-known-certs.zeek` is loaded)

      Set to true to force certificate events to always be raised for this connection.


   .. zeek:field:: requested_client_certificate_authorities :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/protocols/ssl/certificate-request-info.zeek` is loaded)

      List of client certificate CAs accepted by the server


   .. zeek:field:: client_random :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/decryption.zeek` is loaded)


   .. zeek:field:: last_originator_heartbeat_request_size :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: last_responder_heartbeat_request_size :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: originator_heartbeats :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: responder_heartbeats :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: heartbleed_detected :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: enc_appdata_packages :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: enc_appdata_bytes :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


   .. zeek:field:: server_version :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Numeric version of the server in the server hello


   .. zeek:field:: client_version :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Numeric version of the client in the client hello


   .. zeek:field:: client_ciphers :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Ciphers that were offered by the client for the connection


   .. zeek:field:: ssl_client_exts :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      SSL Client extensions


   .. zeek:field:: ssl_server_exts :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      SSL server extensions


   .. zeek:field:: ticket_lifetime_hint :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Suggested ticket lifetime sent in the session ticket handshake
      by the server.


   .. zeek:field:: dh_param_size :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      The diffie helman parameter size, when using DH.


   .. zeek:field:: point_formats :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      supported elliptic curve point formats


   .. zeek:field:: client_curves :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      The curves supported by the client.


   .. zeek:field:: orig_alpn :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Application layer protocol negotiation extension sent by the client.


   .. zeek:field:: client_supported_versions :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      TLS 1.3 supported versions


   .. zeek:field:: server_supported_version :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      TLS 1.3 supported versions


   .. zeek:field:: psk_key_exchange_modes :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      TLS 1.3 Pre-shared key exchange modes


   .. zeek:field:: client_key_share_groups :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Key share groups from client hello


   .. zeek:field:: server_key_share_group :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Selected key share group from server hello


   .. zeek:field:: client_comp_methods :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Client supported compression methods


   .. zeek:field:: comp_method :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Server chosen compression method


   .. zeek:field:: sigalgs :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Client supported signature algorithms


   .. zeek:field:: hashalgs :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/ssl-log-ext.zeek` is loaded)

      Client supported hash algorithms


   .. zeek:field:: validation_status :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` is loaded)

      Result of certificate validation for this connection.


   .. zeek:field:: validation_code :zeek:type:`int` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` is loaded)

      Result of certificate validation for this connection, given
      as OpenSSL validation code.


   .. zeek:field:: valid_chain :zeek:type:`vector` of :zeek:type:`opaque` of x509 :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` is loaded)

      Ordered chain of validated certificate, if validation succeeded.


   .. zeek:field:: ocsp_status :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-ocsp.zeek` is loaded)

      Result of ocsp validation for this connection.


   .. zeek:field:: ocsp_response :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-ocsp.zeek` is loaded)

      ocsp response as string.


   .. zeek:field:: valid_scts :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      Number of valid SCTs that were encountered in the connection.


   .. zeek:field:: invalid_scts :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      Number of SCTs that could not be validated that were encountered in the connection.


   .. zeek:field:: valid_ct_logs :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      Number of different Logs for which valid SCTs were encountered in the connection.


   .. zeek:field:: valid_ct_operators :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      Number of different Log operators of which valid SCTs were encountered in the connection.


   .. zeek:field:: valid_ct_operators_list :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      List of operators for which valid SCTs were encountered in the connection.


   .. zeek:field:: ct_proofs :zeek:type:`vector` of :zeek:type:`SSL::SctInfo` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek` is loaded)

      Information about all SCTs that were encountered in the connection.


   The record type which contains the fields of the SSL log.

Events
######
.. zeek:id:: SSL::log_ssl
   :source-code: base/protocols/ssl/main.zeek 171 171

   :Type: :zeek:type:`event` (rec: :zeek:type:`SSL::Info`)

   Event that can be handled to access the SSL
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: SSL::finalize_ssl
   :source-code: base/protocols/ssl/main.zeek 517 527

   :Type: :zeek:type:`Conn::RemovalHook`

   SSL finalization hook.  Remaining SSL info may get logged when it's called.
   The :zeek:see:`SSL::ssl_finishing` hook may either
   be called before this finalization hook for established SSL connections
   or during this finalization hook for SSL connections may have info still
   left to log.

.. zeek:id:: SSL::log_policy
   :source-code: base/protocols/ssl/main.zeek 24 24

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: SSL::ssl_finishing
   :source-code: base/protocols/ssl/main.zeek 175 175

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   Hook that can be used to perform actions right before the log record
   is written.

Functions
#########
.. zeek:id:: SSL::delay_log
   :source-code: base/protocols/ssl/main.zeek 227 232

   :Type: :zeek:type:`function` (info: :zeek:type:`SSL::Info`, token: :zeek:type:`string`) : :zeek:type:`void`

   Delays an SSL record for a specific token: the record will not be
   logged as long as the token exists or until 15 seconds elapses.

.. zeek:id:: SSL::undelay_log
   :source-code: base/protocols/ssl/main.zeek 234 238

   :Type: :zeek:type:`function` (info: :zeek:type:`SSL::Info`, token: :zeek:type:`string`) : :zeek:type:`void`

   Undelays an SSL record for a previously inserted token, allowing the
   record to be logged.


