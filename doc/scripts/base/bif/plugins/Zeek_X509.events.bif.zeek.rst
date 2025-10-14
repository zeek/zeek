:tocdepth: 3

base/bif/plugins/Zeek_X509.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================================= ================================================================================
:zeek:id:`x509_certificate`: :zeek:type:`event`                           Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
                                                                          connection handshake.
:zeek:id:`x509_ext_basic_constraints`: :zeek:type:`event`                 Generated for the X509 basic constraints extension seen in a certificate.
:zeek:id:`x509_ext_subject_alternative_name`: :zeek:type:`event`          Generated for the X509 subject alternative name extension seen in a certificate.
:zeek:id:`x509_extension`: :zeek:type:`event`                             Generated for X509 extensions seen in a certificate.
:zeek:id:`x509_ocsp_ext_signed_certificate_timestamp`: :zeek:type:`event` Generated for the signed_certificate_timestamp X509 extension as defined in
                                                                          :rfc:`6962`.
========================================================================= ================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: x509_certificate
   :source-code: base/bif/plugins/Zeek_X509.events.bif.zeek 20 20

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, cert_ref: :zeek:type:`opaque` of x509, cert: :zeek:type:`X509::Certificate`)

   Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
   connection handshake.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :param f: The file.
   

   :param cert_ref: An opaque pointer to the underlying OpenSSL data structure of the
             certificate.
   

   :param cert: The parsed certificate information.
   
   .. zeek:see:: x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ext_basic_constraints
   :source-code: base/files/x509/main.zeek 186 193

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::BasicConstraints`)

   Generated for the X509 basic constraints extension seen in a certificate.
   This extension can be used to identify the subject of a certificate as a CA.
   

   :param f: The file.
   

   :param ext: The parsed basic constraints extension.
   
   .. zeek:see:: x509_certificate x509_extension
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ext_subject_alternative_name
   :source-code: base/bif/plugins/Zeek_X509.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::SubjectAlternativeName`)

   Generated for the X509 subject alternative name extension seen in a certificate.
   This extension can be used to allow additional entities to be bound to the
   subject of the certificate. Usually it is used to specify one or multiple DNS
   names for which a certificate is valid.
   

   :param f: The file.
   

   :param ext: The parsed subject alternative name extension.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ocsp_ext_signed_certificate_timestamp
                x509_get_certificate_string

.. zeek:id:: x509_extension
   :source-code: base/files/x509/main.zeek 177 184

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::Extension`)

   Generated for X509 extensions seen in a certificate.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :param f: The file.
   

   :param ext: The parsed extension.
   
   .. zeek:see:: x509_certificate x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ocsp_ext_signed_certificate_timestamp
   :source-code: base/bif/plugins/Zeek_X509.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, version: :zeek:type:`count`, logid: :zeek:type:`string`, timestamp: :zeek:type:`count`, hash_algorithm: :zeek:type:`count`, signature_algorithm: :zeek:type:`count`, signature: :zeek:type:`string`)

   Generated for the signed_certificate_timestamp X509 extension as defined in
   :rfc:`6962`. The extension is used to transmit signed proofs that are
   used for Certificate Transparency. Raised when the extension is encountered
   in an X.509 certificate or in an OCSP reply.
   

   :param f: The file.
   

   :param version: the version of the protocol to which the SCT conforms. Always
            should be 0 (representing version 1)
   

   :param logid: 32 bit key id
   

   :param timestamp: the NTP Time when the entry was logged measured since
              the epoch, ignoring leap seconds, in milliseconds.
   

   :param signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct
   

   :param signature: signature part of the digitally_signed struct
   
   .. zeek:see:: ssl_extension_signed_certificate_timestamp x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ext_subject_alternative_name
                x509_get_certificate_string ssl_extension_signed_certificate_timestamp
                sct_verify ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp


