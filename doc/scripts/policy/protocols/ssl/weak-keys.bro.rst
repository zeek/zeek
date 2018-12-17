:tocdepth: 3

policy/protocols/ssl/weak-keys.bro
==================================
.. bro:namespace:: SSL

Generate notices when SSL/TLS connections use certificates, DH parameters,
or cipher suites that are deemed to be insecure.

:Namespace: SSL
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================== ==============================================================================
:bro:id:`SSL::notify_dh_length_shorter_cert_length`: :bro:type:`bool` :bro:attr:`&redef` Warn if the DH key length is smaller than the certificate key length.
:bro:id:`SSL::notify_minimal_key_length`: :bro:type:`count` :bro:attr:`&redef`           The minimal key length in bits that is considered to be safe.
:bro:id:`SSL::notify_weak_keys`: :bro:type:`Host` :bro:attr:`&redef`                     The category of hosts you would like to be notified about which are using weak
                                                                                         keys/ciphers/protocol_versions.
:bro:id:`SSL::tls_minimum_version`: :bro:type:`count` :bro:attr:`&redef`                 Warn if a server negotiates a SSL session with a protocol version smaller than
                                                                                         the specified version.
:bro:id:`SSL::unsafe_ciphers_regex`: :bro:type:`pattern` :bro:attr:`&redef`              Warn if a server negotiates an unsafe cipher suite.
======================================================================================== ==============================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSL::notify_dh_length_shorter_cert_length

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Warn if the DH key length is smaller than the certificate key length. This is
   potentially unsafe because it gives a wrong impression of safety due to the
   certificate key length. However, it is very common and cannot be avoided in some
   settings (e.g. with old jave clients).

.. bro:id:: SSL::notify_minimal_key_length

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2048``

   The minimal key length in bits that is considered to be safe. Any shorter
   (non-EC) key lengths will trigger a notice.

.. bro:id:: SSL::notify_weak_keys

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   The category of hosts you would like to be notified about which are using weak
   keys/ciphers/protocol_versions.  By default, these notices will be suppressed
   by the notice framework for 1 day after a particular host has had a notice
   generated. Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS

.. bro:id:: SSL::tls_minimum_version

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``769``

   Warn if a server negotiates a SSL session with a protocol version smaller than
   the specified version. By default, the minimal version is TLSv10 because SSLv2
   and v3 have serious security issued.
   See https://tools.ietf.org/html/draft-thomson-sslv3-diediedie-00
   To disable, set to SSLv20

.. bro:id:: SSL::unsafe_ciphers_regex

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((_EXPORT_)|(_RC4_))$?/

   Warn if a server negotiates an unsafe cipher suite. By default, we only warn when
   encountering old export cipher suites, or RC4 (see RFC7465).


