:tocdepth: 3

base/bif/plugins/Bro_X509.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================================= ================================================================================
:bro:id:`x509_certificate`: :bro:type:`event`                           Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
                                                                        connection handshake.
:bro:id:`x509_ext_basic_constraints`: :bro:type:`event`                 Generated for the X509 basic constraints extension seen in a certificate.
:bro:id:`x509_ext_subject_alternative_name`: :bro:type:`event`          Generated for the X509 subject alternative name extension seen in a certificate.
:bro:id:`x509_extension`: :bro:type:`event`                             Generated for X509 extensions seen in a certificate.
:bro:id:`x509_ocsp_ext_signed_certificate_timestamp`: :bro:type:`event` Generated for the signed_certificate_timestamp X509 extension as defined in
                                                                        :rfc:`6962`.
======================================================================= ================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: x509_certificate

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, cert_ref: :bro:type:`opaque` of x509, cert: :bro:type:`X509::Certificate`)

   Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
   connection handshake.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :f: The file.
   

   :cert_ref: An opaque pointer to the underlying OpenSSL data structure of the
             certificate.
   

   :cert: The parsed certificate information.
   
   .. bro:see:: x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: x509_ext_basic_constraints

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ext: :bro:type:`X509::BasicConstraints`)

   Generated for the X509 basic constraints extension seen in a certificate.
   This extension can be used to identify the subject of a certificate as a CA.
   

   :f: The file.
   

   :ext: The parsed basic constraints extension.
   
   .. bro:see:: x509_certificate x509_extension
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: x509_ext_subject_alternative_name

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ext: :bro:type:`X509::SubjectAlternativeName`)

   Generated for the X509 subject alternative name extension seen in a certificate.
   This extension can be used to allow additional entities to be bound to the
   subject of the certificate. Usually it is used to specify one or multiple DNS
   names for which a certificate is valid.
   

   :f: The file.
   

   :ext: The parsed subject alternative name extension.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ocsp_ext_signed_certificate_timestamp
                x509_get_certificate_string

.. bro:id:: x509_extension

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ext: :bro:type:`X509::Extension`)

   Generated for X509 extensions seen in a certificate.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :f: The file.
   

   :ext: The parsed extension.
   
   .. bro:see:: x509_certificate x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: x509_ocsp_ext_signed_certificate_timestamp

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, version: :bro:type:`count`, logid: :bro:type:`string`, timestamp: :bro:type:`count`, hash_algorithm: :bro:type:`count`, signature_algorithm: :bro:type:`count`, signature: :bro:type:`string`)

   Generated for the signed_certificate_timestamp X509 extension as defined in
   :rfc:`6962`. The extension is used to transmit signed proofs that are
   used for Certificate Transparency. Raised when the extension is encountered
   in an X.509 certificate or in an OCSP reply.
   

   :f: The file.
   

   :version: the version of the protocol to which the SCT conforms. Always
            should be 0 (representing version 1)
   

   :logid: 32 bit key id
   

   :timestamp: the NTP Time when the entry was logged measured since
              the epoch, ignoring leap seconds, in milliseconds.
   

   :signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct
   

   :signature: signature part of the digitally_signed struct
   
   .. bro:see:: ssl_extension_signed_certificate_timestamp x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ext_subject_alternative_name
                x509_get_certificate_string ssl_extension_signed_certificate_timestamp
                sct_verify ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp


