:tocdepth: 3

base/bif/plugins/Bro_X509.functions.bif.bro
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=========================================================== =============================================================================
:bro:id:`sct_verify`: :bro:type:`function`                  Verifies a Signed Certificate Timestamp as used for Certificate Transparency.
:bro:id:`x509_get_certificate_string`: :bro:type:`function` Returns the string form of a certificate.
:bro:id:`x509_issuer_name_hash`: :bro:type:`function`       Get the hash of the issuer's distinguished name.
:bro:id:`x509_ocsp_verify`: :bro:type:`function`            Verifies an OCSP reply.
:bro:id:`x509_parse`: :bro:type:`function`                  Parses a certificate into an X509::Certificate structure.
:bro:id:`x509_spki_hash`: :bro:type:`function`              Get the hash of the Subject Public Key Information of the certificate.
:bro:id:`x509_subject_name_hash`: :bro:type:`function`      Get the hash of the subject's distinguished name.
:bro:id:`x509_verify`: :bro:type:`function`                 Verifies a certificate.
=========================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: sct_verify

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, logid: :bro:type:`string`, log_key: :bro:type:`string`, signature: :bro:type:`string`, timestamp: :bro:type:`count`, hash_algorithm: :bro:type:`count`, issuer_key_hash: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Verifies a Signed Certificate Timestamp as used for Certificate Transparency.
   See RFC6962 for more details.
   

   :cert: Certificate against which the SCT should be validated.
   

   :logid: Log id of the SCT.
   

   :log_key: Public key of the Log that issued the SCT proof.
   

   :timestamp: Timestamp at which the proof was generated.
   

   :hash_algorithm: Hash algorithm that was used for the SCT proof.
   

   :issuer_key_hash: The SHA-256 hash of the certificate issuer's public key.
                    This only has to be provided if the SCT was encountered in an X.509
                    certificate extension; in that case, it is necessary for validation.
   

   :returns: T if the validation could be performed succesfully, F otherwhise.
   
   .. bro:see:: ssl_extension_signed_certificate_timestamp
                x509_ocsp_ext_signed_certificate_timestamp
                x509_verify

.. bro:id:: x509_get_certificate_string

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, pem: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`) : :bro:type:`string`

   Returns the string form of a certificate.
   

   :cert: The X509 certificate opaque handle.
   

   :pem: A boolean that specifies if the certificate is returned
        in pem-form (true), or as the raw ASN1 encoded binary
        (false).
   

   :returns: X509 certificate as a string.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify

.. bro:id:: x509_issuer_name_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the issuer's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_subject_name_hash x509_spki_hash
                x509_verify sct_verify

.. bro:id:: x509_ocsp_verify

   :Type: :bro:type:`function` (certs: :bro:type:`x509_opaque_vector`, ocsp_reply: :bro:type:`string`, root_certs: :bro:type:`table_string_of_string`, verify_time: :bro:type:`time` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`) : :bro:type:`X509::Result`

   Verifies an OCSP reply.
   

   :certs: Specifies the certificate chain to use. Server certificate first.
   

   :ocsp_reply: the ocsp reply to validate.
   

   :root_certs: A list of root certificates to validate the certificate chain.
   

   :verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_verify

.. bro:id:: x509_parse

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509) : :bro:type:`X509::Certificate`

   Parses a certificate into an X509::Certificate structure.
   

   :cert: The X509 certificate opaque handle.
   

   :returns: A X509::Certificate structure.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string

.. bro:id:: x509_spki_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the Subject Public Key Information of the certificate.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_subject_name_hash x509_issuer_name_hash
                x509_verify sct_verify

.. bro:id:: x509_subject_name_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the subject's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_issuer_name_hash x509_spki_hash
                x509_verify sct_verify

.. bro:id:: x509_verify

   :Type: :bro:type:`function` (certs: :bro:type:`x509_opaque_vector`, root_certs: :bro:type:`table_string_of_string`, verify_time: :bro:type:`time` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`) : :bro:type:`X509::Result`

   Verifies a certificate.
   

   :certs: Specifies a certificate chain that is being used to validate
          the given certificate against the root store given in *root_certs*.
          The host certificate has to be at index 0.
   

   :root_certs: A list of root certificates to validate the certificate chain.
   

   :verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation. In case of success also returns the full
            certificate chain.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_ocsp_verify sct_verify


