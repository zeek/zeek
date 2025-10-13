:tocdepth: 3

policy/protocols/ssl/weak-keys.zeek
===================================
.. zeek:namespace:: SSL

Generate notices when SSL/TLS connections use certificates, DH parameters,
or cipher suites that are deemed to be insecure.

:Namespace: SSL
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================================== ==============================================================================
:zeek:id:`SSL::notify_dh_length_shorter_cert_length`: :zeek:type:`bool` :zeek:attr:`&redef` Warn if the DH key length is smaller than the certificate key length.
:zeek:id:`SSL::notify_minimal_key_length`: :zeek:type:`count` :zeek:attr:`&redef`           The minimal key length in bits that is considered to be safe.
:zeek:id:`SSL::notify_weak_keys`: :zeek:type:`Host` :zeek:attr:`&redef`                     The category of hosts you would like to be notified about which are using weak
                                                                                            keys/ciphers/protocol_versions.
:zeek:id:`SSL::tls_minimum_version`: :zeek:type:`count` :zeek:attr:`&redef`                 Warn if a server negotiates a SSL session with a protocol version smaller than
                                                                                            the specified version.
:zeek:id:`SSL::unsafe_ciphers_regex`: :zeek:type:`pattern` :zeek:attr:`&redef`              Warn if a server negotiates an unsafe cipher suite.
=========================================================================================== ==============================================================================

Redefinitions
#############
============================================ ===============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSL::Old_Version`:
                                               Indicates that a server is using a potentially unsafe version
                                             
                                             * :zeek:enum:`SSL::Weak_Cipher`:
                                               Indicates that a server is using a potentially unsafe cipher
                                             
                                             * :zeek:enum:`SSL::Weak_Key`:
                                               Indicates that a server is using a potentially unsafe key.
============================================ ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSL::notify_dh_length_shorter_cert_length
   :source-code: policy/protocols/ssl/weak-keys.zeek 34 34

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Warn if the DH key length is smaller than the certificate key length. This is
   potentially unsafe because it gives a wrong impression of safety due to the
   certificate key length. However, it is very common and cannot be avoided in some
   settings (e.g. with old java clients).

.. zeek:id:: SSL::notify_minimal_key_length
   :source-code: policy/protocols/ssl/weak-keys.zeek 28 28

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2048``

   The minimal key length in bits that is considered to be safe. Any shorter
   (non-EC) key lengths will trigger a notice.

.. zeek:id:: SSL::notify_weak_keys
   :source-code: policy/protocols/ssl/weak-keys.zeek 24 24

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   The category of hosts you would like to be notified about which are using weak
   keys/ciphers/protocol_versions.  By default, these notices will be suppressed
   by the notice framework for 1 day after a particular host has had a notice
   generated. Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS

.. zeek:id:: SSL::tls_minimum_version
   :source-code: policy/protocols/ssl/weak-keys.zeek 41 41

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``769``

   Warn if a server negotiates a SSL session with a protocol version smaller than
   the specified version. By default, the minimal version is TLSv10 because SSLv2
   and v3 have serious security issued.
   See https://tools.ietf.org/html/draft-thomson-sslv3-diediedie-00
   To disable, set to SSLv20

.. zeek:id:: SSL::unsafe_ciphers_regex
   :source-code: policy/protocols/ssl/weak-keys.zeek 45 45

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((_EXPORT_)|(_RC4_))$?/


   Warn if a server negotiates an unsafe cipher suite. By default, we only warn when
   encountering old export cipher suites, or RC4 (see RFC7465).


