:tocdepth: 3

base/bif/plugins/Zeek_SSL.functions.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ==============================================================================
:zeek:id:`parse_distinguished_name`: :zeek:type:`function` Decodes a DER-encoded distinguished name into an ASCII string,
                                                           using the RFC2253 representation
:zeek:id:`set_keys`: :zeek:type:`function`                 Set the decryption keys that should be used to decrypt
                                                           TLS application data in the connection.
:zeek:id:`set_secret`: :zeek:type:`function`               Set the secret that should be used to derive keys for the connection.
:zeek:id:`set_ssl_established`: :zeek:type:`function`      Sets if the SSL analyzer should consider the connection established (handshake
                                                           finished successfully).
========================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: parse_distinguished_name
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 46 46

   :Type: :zeek:type:`function` (dn: :zeek:type:`string`) : :zeek:type:`string`

   Decodes a DER-encoded distinguished name into an ASCII string,
   using the RFC2253 representation
   

   :param dn: DER encoded distinguished name
   

   :returns: Ascii representation on success, empty string on failure
   
   .. zeek:see:: ssl_certificate_request

.. zeek:id:: set_keys
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, keys: :zeek:type:`string`) : :zeek:type:`bool`

   Set the decryption keys that should be used to decrypt
   TLS application data in the connection.
   

   :param c: The affected connection
   

   :param keys: The key buffer as derived via TLS PRF.
   

   :returns: T on success, F on failure.

.. zeek:id:: set_secret
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, secret: :zeek:type:`string`) : :zeek:type:`bool`

   Set the secret that should be used to derive keys for the connection.
   (For TLS 1.2 this is the pre-master secret).
   

   :param c: The affected connection
   

   :param secret: secret to set
   

   :returns: T on success, F on failure.

.. zeek:id:: set_ssl_established
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 13 13

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished successfully).
   

   :param c: The SSL connection.
   

   :returns: T on success, F on failure.


