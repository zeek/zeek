:tocdepth: 3

base/files/x509/main.zeek
=========================
.. zeek:namespace:: X509


:Namespace: X509
:Imports: :doc:`base/files/hash </scripts/base/files/hash/index>`, :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================================== ===================================================================
:zeek:id:`X509::known_log_certs_maximum_size`: :zeek:type:`count` :zeek:attr:`&redef`      Maximum size of the known_log_certs table
:zeek:id:`X509::log_x509_in_files_log`: :zeek:type:`bool` :zeek:attr:`&redef`              This option specifies if X.509 certificates are logged in file.log.
:zeek:id:`X509::relog_known_certificates_after`: :zeek:type:`interval` :zeek:attr:`&redef` By default, x509 certificates are deduplicated.
========================================================================================== ===================================================================

State Variables
###############
================================================================================================================================= ===========================================================================================
:zeek:id:`X509::known_log_certs`: :zeek:type:`set` :zeek:attr:`&create_expire` = :zeek:see:`X509::relog_known_certificates_after` The set that stores information about certificates that already have been logged and should
                                                                                                                                  not be logged again.
:zeek:id:`X509::known_log_certs_use_broker`: :zeek:type:`bool`                                                                    Use broker stores to deduplicate certificates across the whole cluster.
================================================================================================================================= ===========================================================================================

Types
#####
=================================================== ===================================================================================
:zeek:type:`X509::Info`: :zeek:type:`record`        The record type which contains the fields of the X.509 log.
:zeek:type:`X509::LogCertHash`: :zeek:type:`record` Type that is used to decide which certificates are duplicates for logging purposes.
:zeek:type:`X509::SctInfo`: :zeek:type:`record`     This record is used to store information about the SCTs that are
                                                    encountered in Certificates.
=================================================== ===================================================================================

Redefinitions
#############
================================================================= ======================================================
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                  
                                                                  :New Fields: :zeek:type:`Files::Info`
                                                                  
                                                                    x509: :zeek:type:`X509::Info` :zeek:attr:`&optional`
                                                                      Information about X509 certificates.
:zeek:type:`Log::ID`: :zeek:type:`enum`                           
                                                                  
                                                                  * :zeek:enum:`X509::LOG`
================================================================= ======================================================

Events
######
============================================= ===================================
:zeek:id:`X509::log_x509`: :zeek:type:`event` Event for accessing logged records.
============================================= ===================================

Hooks
#####
============================================================== =======================================================================
:zeek:id:`X509::create_deduplication_index`: :zeek:type:`hook` Hook that is used to create the index value used for log deduplication.
:zeek:id:`X509::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================================================================

Functions
#########
========================================================================= ==============================================
:zeek:id:`X509::hash_function`: :zeek:type:`function` :zeek:attr:`&redef` The hash function used for certificate hashes.
========================================================================= ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: X509::known_log_certs_maximum_size
   :source-code: base/files/x509/main.zeek 98 98

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000000``

   Maximum size of the known_log_certs table

.. zeek:id:: X509::log_x509_in_files_log
   :source-code: base/files/x509/main.zeek 20 20

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   This option specifies if X.509 certificates are logged in file.log. Typically, there
   is not much value to having the entry in files.log - especially since, by default, the
   file ID is not present in the X509 log.

.. zeek:id:: X509::relog_known_certificates_after
   :source-code: base/files/x509/main.zeek 91 91

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   By default, x509 certificates are deduplicated. This configuration option configures
   the maximum time after which certificates are re-logged. Note - depending on other configuration
   options, this setting might only apply on a per-worker basis and you still might see certificates
   logged several times.
   
   To disable deduplication completely, set this to 0secs.

State Variables
###############
.. zeek:id:: X509::known_log_certs
   :source-code: base/files/x509/main.zeek 95 95

   :Type: :zeek:type:`set` [:zeek:type:`X509::LogCertHash`]
   :Attributes: :zeek:attr:`&create_expire` = :zeek:see:`X509::relog_known_certificates_after`
   :Default: ``{}``

   The set that stores information about certificates that already have been logged and should
   not be logged again.

.. zeek:id:: X509::known_log_certs_use_broker
   :source-code: base/files/x509/main.zeek 104 104

   :Type: :zeek:type:`bool`
   :Default: ``T``

   Use broker stores to deduplicate certificates across the whole cluster. This will cause log-deduplication
   to work cluster wide, but come at a slightly higher cost of memory and inter-node-communication.
   
   This setting is ignored if Zeek is run in standalone mode.

Types
#####
.. zeek:type:: X509::Info
   :source-code: base/files/x509/main.zeek 34 60

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Current timestamp.

      fingerprint: :zeek:type:`string` :zeek:attr:`&log`
         Fingerprint of the certificate - uses chosen algorithm.

      certificate: :zeek:type:`X509::Certificate` :zeek:attr:`&log`
         Basic information about the certificate.

      handle: :zeek:type:`opaque` of x509
         The opaque wrapping the certificate. Mainly used
         for the verify operations.

      extensions: :zeek:type:`vector` of :zeek:type:`X509::Extension` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         All extensions that were encountered in the certificate.

      san: :zeek:type:`X509::SubjectAlternativeName` :zeek:attr:`&optional` :zeek:attr:`&log`
         Subject alternative name extension of the certificate.

      basic_constraints: :zeek:type:`X509::BasicConstraints` :zeek:attr:`&optional` :zeek:attr:`&log`
         Basic constraints extension of the certificate.

      extensions_cache: :zeek:type:`vector` of :zeek:type:`any` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         All extensions in the order they were raised.
         This is used for caching certificates that are commonly
         encountered and should not be relied on in user scripts.

      host_cert: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates if this certificate was a end-host certificate, or sent as part of a chain

      client_cert: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates if this certificate was sent from the client

      deduplication_index: :zeek:type:`X509::LogCertHash` :zeek:attr:`&optional`
         Record that is used to deduplicate log entries.

      always_raise_x509_events: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/files/x509/disable-certificate-events-known-certs.zeek` is loaded)

         Set to true to force certificate events to always be raised for this certificate.

      cert: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-certs-base64.zeek` is loaded)

         Base64 encoded X.509 certificate.

   The record type which contains the fields of the X.509 log.

.. zeek:type:: X509::LogCertHash
   :source-code: base/files/x509/main.zeek 24 31

   :Type: :zeek:type:`record`

      fingerprint: :zeek:type:`string`
         Certificate fingerprint

      host_cert: :zeek:type:`bool`
         Indicates if this certificate was a end-host certificate, or sent as part of a chain

      client_cert: :zeek:type:`bool`
         Indicates if this certificate was sent from the client

   Type that is used to decide which certificates are duplicates for logging purposes.
   When adding entries to this, also change the create_deduplication_index to update them.

.. zeek:type:: X509::SctInfo
   :source-code: base/files/x509/main.zeek 67 83

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The version of the encountered SCT (should always be 0 for v1).

      logid: :zeek:type:`string`
         The ID of the log issuing this SCT.

      timestamp: :zeek:type:`count`
         The timestamp at which this SCT was issued measured since the
         epoch (January 1, 1970, 00:00), ignoring leap seconds, in
         milliseconds. Not converted to a Zeek timestamp because we need
         the exact value for validation.

      hash_alg: :zeek:type:`count`
         The hash algorithm used for this sct.

      sig_alg: :zeek:type:`count`
         The signature algorithm used for this sct.

      signature: :zeek:type:`string`
         The signature of this SCT.

   This record is used to store information about the SCTs that are
   encountered in Certificates.

Events
######
.. zeek:id:: X509::log_x509
   :source-code: base/files/x509/main.zeek 107 107

   :Type: :zeek:type:`event` (rec: :zeek:type:`X509::Info`)

   Event for accessing logged records.

Hooks
#####
.. zeek:id:: X509::create_deduplication_index
   :source-code: base/files/x509/main.zeek 158 164

   :Type: :zeek:type:`hook` (c: :zeek:type:`X509::Info`) : :zeek:type:`bool`

   Hook that is used to create the index value used for log deduplication.

.. zeek:id:: X509::log_policy
   :source-code: policy/protocols/ssl/log-hostcerts-only.zeek 9 13

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: X509::hash_function
   :source-code: base/files/x509/main.zeek 15 15

   :Type: :zeek:type:`function` (cert: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   The hash function used for certificate hashes. By default this is sha256; you can use
   any other hash function and the hashes will change in ssl.log and in x509.log.


