:tocdepth: 3

policy/protocols/ssl/decryption.zeek
====================================
.. zeek:namespace:: SSL

This script allows for the decryption of certain TLS 1.2 connections, if the user is in possession
of the private key material for the session. Key material can either be provided via a file (useful
for processing trace files) or via sending events via Broker (for live decoding).

Please note that this feature is experimental and can change without guarantees to our typical
deprecation timeline. Please also note that currently only TLS 1.2 connections that use the
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 cipher suite are supported.

:Namespace: SSL
:Imports: :doc:`base/frameworks/input </scripts/base/frameworks/input/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ =====================================================================================================
:zeek:id:`SSL::keylog_file`: :zeek:type:`string` :zeek:attr:`&redef`         This can be set to a file that contains the session secrets for decryption, when parsing a pcap file.
:zeek:id:`SSL::secret_expiration`: :zeek:type:`interval` :zeek:attr:`&redef` Secrets expire after this time of not being used.
============================================================================ =====================================================================================================

Redefinitions
#############
======================================================================================= ===========================================================
:zeek:type:`SSL::Info`: :zeek:type:`record`                                             
                                                                                        
                                                                                        :New Fields: :zeek:type:`SSL::Info`
                                                                                        
                                                                                          client_random: :zeek:type:`string` :zeek:attr:`&optional`
:zeek:id:`SSL::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` 
======================================================================================= ===========================================================

Events
######
============================================== ==============================================================================================
:zeek:id:`SSL::add_keys`: :zeek:type:`event`   This event can be triggered, e.g., via Broker to add known keys to the TLS key database.
:zeek:id:`SSL::add_secret`: :zeek:type:`event` This event can be triggered, e.g., via Broker to add known secrets to the TLS secret database.
============================================== ==============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SSL::keylog_file
   :source-code: policy/protocols/ssl/decryption.zeek 24 24

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This can be set to a file that contains the session secrets for decryption, when parsing a pcap file.
   Please note that, when using this feature, you probably want to pause processing of data till this
   file has been read.

.. zeek:id:: SSL::secret_expiration
   :source-code: policy/protocols/ssl/decryption.zeek 27 27

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   Secrets expire after this time of not being used.

Events
######
.. zeek:id:: SSL::add_keys
   :source-code: policy/protocols/ssl/decryption.zeek 82 85

   :Type: :zeek:type:`event` (client_random: :zeek:type:`string`, keys: :zeek:type:`string`)

   This event can be triggered, e.g., via Broker to add known keys to the TLS key database.
   

   :param client_random: client random for which the key is set
   

   :param keys: key material

.. zeek:id:: SSL::add_secret
   :source-code: policy/protocols/ssl/decryption.zeek 87 90

   :Type: :zeek:type:`event` (client_random: :zeek:type:`string`, secrets: :zeek:type:`string`)

   This event can be triggered, e.g., via Broker to add known secrets to the TLS secret database.
   

   :param client_random: client random for which the secret is set
   

   :param secrets: derived TLS secrets material


