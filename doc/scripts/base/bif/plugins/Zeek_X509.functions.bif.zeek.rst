:tocdepth: 3

base/bif/plugins/Zeek_X509.functions.bif.zeek
=============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================================= ================================================================================================
:zeek:id:`sct_verify`: :zeek:type:`function`                              Verifies a Signed Certificate Timestamp as used for Certificate Transparency.
:zeek:id:`x509_check_cert_hostname`: :zeek:type:`function`                This function checks if a hostname matches one of the hostnames given in the certificate.
:zeek:id:`x509_check_hostname`: :zeek:type:`function`                     This function checks a hostname against the name given in a certificate subject/SAN, including
                                                                          our interpretation of RFC6128 wildcard expansions.
:zeek:id:`x509_from_der`: :zeek:type:`function`                           Constructs an opaque of X509 from a der-formatted string.
:zeek:id:`x509_get_certificate_string`: :zeek:type:`function`             Returns the string form of a certificate.
:zeek:id:`x509_issuer_name_hash`: :zeek:type:`function`                   Get the hash of the issuer's distinguished name.
:zeek:id:`x509_ocsp_verify`: :zeek:type:`function`                        Verifies an OCSP reply.
:zeek:id:`x509_parse`: :zeek:type:`function`                              Parses a certificate into an X509::Certificate structure.
:zeek:id:`x509_set_certificate_cache`: :zeek:type:`function`              This function can be used to set up certificate caching.
:zeek:id:`x509_set_certificate_cache_hit_callback`: :zeek:type:`function` This function sets up the callback that is called when an entry is matched against the table set
                                                                          by :zeek:id:`x509_set_certificate_cache`.
:zeek:id:`x509_spki_hash`: :zeek:type:`function`                          Get the hash of the Subject Public Key Information of the certificate.
:zeek:id:`x509_subject_name_hash`: :zeek:type:`function`                  Get the hash of the subject's distinguished name.
:zeek:id:`x509_verify`: :zeek:type:`function`                             Verifies a certificate.
========================================================================= ================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: sct_verify
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 104 104

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, logid: :zeek:type:`string`, log_key: :zeek:type:`string`, signature: :zeek:type:`string`, timestamp: :zeek:type:`count`, hash_algorithm: :zeek:type:`count`, issuer_key_hash: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Verifies a Signed Certificate Timestamp as used for Certificate Transparency.
   See RFC6962 for more details.
   

   :param cert: Certificate against which the SCT should be validated.
   

   :param logid: Log id of the SCT.
   

   :param log_key: Public key of the Log that issued the SCT proof.
   

   :param timestamp: Timestamp at which the proof was generated.
   

   :param hash_algorithm: Hash algorithm that was used for the SCT proof.
   

   :param issuer_key_hash: The SHA-256 hash of the certificate issuer's public key.
                    This only has to be provided if the SCT was encountered in an X.509
                    certificate extension; in that case, it is necessary for validation.
   

   :returns: T if the validation could be performed successfully, F otherwise.
   
   .. zeek:see:: ssl_extension_signed_certificate_timestamp
                x509_ocsp_ext_signed_certificate_timestamp
                x509_verify

.. zeek:id:: x509_check_cert_hostname
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 216 216

   :Type: :zeek:type:`function` (cert_opaque: :zeek:type:`opaque` of x509, hostname: :zeek:type:`string`) : :zeek:type:`string`

   This function checks if a hostname matches one of the hostnames given in the certificate.
   
   For our matching we adhere to RFC6128 for the labels (see :zeek:id:`x509_check_hostname`).
   Furthermore we adhere to RFC2818 and check only the names given in the SAN, if a SAN is present,
   ignoring CNs in the Subject. If no SAN is present, we will use the last CN in the subject
   for our tests.
   

   :param cert: The X509 certificate opaque handle.
   

   :param hostname: Hostname to check
   

   :returns: empty string if the hostname does not match; matched name (which can contain wildcards)
            if it did.
   
   .. zeek:see:: x509_check_hostname

.. zeek:id:: x509_check_hostname
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 198 198

   :Type: :zeek:type:`function` (hostname: :zeek:type:`string`, certname: :zeek:type:`string`) : :zeek:type:`bool`

   This function checks a hostname against the name given in a certificate subject/SAN, including
   our interpretation of RFC6128 wildcard expansions. This specifically means that wildcards are
   only allowed in the leftmost label, wildcards only span one label, the wildcard has to be the
   last character before the label-separator, but additional characters are allowed before it, and
   the wildcard has to be at least at the third level (so \*.a.b).
   

   :param hostname: Hostname to test
   

   :param certname: Name given in the CN/SAN of a certificate; wildcards will be expanded
   

   :returns: True if the hostname matches.
   
   .. zeek:see:: x509_check_cert_hostname

.. zeek:id:: x509_from_der
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 25 25

   :Type: :zeek:type:`function` (der: :zeek:type:`string`) : :zeek:type:`opaque` of x509

   Constructs an opaque of X509 from a der-formatted string.
   

   :param Note: this function is mostly meant for testing purposes
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string x509_parse

.. zeek:id:: x509_get_certificate_string
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 40 40

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, pem: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns the string form of a certificate.
   

   :param cert: The X509 certificate opaque handle.
   

   :param pem: A boolean that specifies if the certificate is returned
        in pem-form (true), or as the raw ASN1 encoded binary
        (false).
   

   :returns: X509 certificate as a string.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify

.. zeek:id:: x509_issuer_name_hash
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 135 135

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the issuer's distinguished name.
   

   :param cert: The X509 certificate opaque handle.
   

   :param hash_alg: the hash algorithm to use, according to the IANA mapping at

             :param https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_subject_name_hash x509_spki_hash
                x509_verify sct_verify

.. zeek:id:: x509_ocsp_verify
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 59 59

   :Type: :zeek:type:`function` (certs: :zeek:type:`x509_opaque_vector`, ocsp_reply: :zeek:type:`string`, root_certs: :zeek:type:`table_string_of_string`, verify_time: :zeek:type:`time` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`) : :zeek:type:`X509::Result`

   Verifies an OCSP reply.
   

   :param certs: Specifies the certificate chain to use. Server certificate first.
   

   :param ocsp_reply: the ocsp reply to validate.
   

   :param root_certs: A list of root certificates to validate the certificate chain.
   

   :param verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_verify

.. zeek:id:: x509_parse
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509) : :zeek:type:`X509::Certificate`

   Parses a certificate into an X509::Certificate structure.
   

   :param cert: The X509 certificate opaque handle.
   

   :returns: A X509::Certificate structure.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string

.. zeek:id:: x509_set_certificate_cache
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 168 168

   :Type: :zeek:type:`function` (tbl: :zeek:type:`string_any_table`) : :zeek:type:`bool`

   This function can be used to set up certificate caching. It has to be passed a table[string] which
   can contain any type.
   
   After this is set up, for each certificate encountered, the X509 analyzer will check if the entry
   tbl[sha256 of certificate] is set. If this is the case, the X509 analyzer will skip all further
   processing, and instead just call the callback that is set with

   :param zeek:id:`x509_set_certificate_cache_hit_callback`.
   

   :param tbl: Table to use as the certificate cache.
   

   :returns: Always returns true.
   
   .. note:: The base scripts use this function to set up certificate caching. You should only change the
             cache table if you are sure you will not conflict with the base scripts.
   
   .. zeek:see:: x509_set_certificate_cache_hit_callback

.. zeek:id:: x509_set_certificate_cache_hit_callback
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 182 182

   :Type: :zeek:type:`function` (f: :zeek:type:`string_any_file_hook`) : :zeek:type:`bool`

   This function sets up the callback that is called when an entry is matched against the table set
   by :zeek:id:`x509_set_certificate_cache`.
   

   :param f: The callback that will be called when encountering a certificate in the cache table.
   

   :returns: Always returns true.
   
   .. note:: The base scripts use this function to set up certificate caching. You should only change the
             callback function if you are sure you will not conflict with the base scripts.
   
   .. zeek:see:: x509_set_certificate_cache

.. zeek:id:: x509_spki_hash
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 149 149

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the Subject Public Key Information of the certificate.
   

   :param cert: The X509 certificate opaque handle.
   

   :param hash_alg: the hash algorithm to use, according to the IANA mapping at

             :param https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_subject_name_hash x509_issuer_name_hash
                x509_verify sct_verify

.. zeek:id:: x509_subject_name_hash
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 121 121

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the subject's distinguished name.
   

   :param cert: The X509 certificate opaque handle.
   

   :param hash_alg: the hash algorithm to use, according to the IANA mapping at

             :param https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_issuer_name_hash x509_spki_hash
                x509_verify sct_verify

.. zeek:id:: x509_verify
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 79 79

   :Type: :zeek:type:`function` (certs: :zeek:type:`x509_opaque_vector`, root_certs: :zeek:type:`table_string_of_string`, verify_time: :zeek:type:`time` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`) : :zeek:type:`X509::Result`

   Verifies a certificate.
   

   :param certs: Specifies a certificate chain that is being used to validate
          the given certificate against the root store given in *root_certs*.
          The host certificate has to be at index 0.
   

   :param root_certs: A list of root certificates to validate the certificate chain.
   

   :param verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation. In case of success also returns the full
            certificate chain.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_ocsp_verify sct_verify


