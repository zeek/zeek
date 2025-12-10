File Analyzers
==============

.. zeek:type:: Files::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Files::ANALYZER_DATA_EVENT Files::Tag

      .. zeek:enum:: Files::ANALYZER_ENTROPY Files::Tag

      .. zeek:enum:: Files::ANALYZER_EXTRACT Files::Tag

      .. zeek:enum:: Files::ANALYZER_MD5 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA1 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA224 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA256 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA384 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA512 Files::Tag

      .. zeek:enum:: Files::ANALYZER_PE Files::Tag

      .. zeek:enum:: Files::ANALYZER_OCSP_REPLY Files::Tag

      .. zeek:enum:: Files::ANALYZER_OCSP_REQUEST Files::Tag

      .. zeek:enum:: Files::ANALYZER_X509 Files::Tag

.. _plugin-zeek-filedataevent:

Zeek::FileDataEvent
-------------------

Delivers file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_DATA_EVENT`

.. _plugin-zeek-fileentropy:

Zeek::FileEntropy
-----------------

Entropy test file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_ENTROPY`

Events
++++++

.. zeek:id:: file_entropy
   :source-code: policy/frameworks/files/entropy-test-all-files.zeek 16 19

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ent: :zeek:type:`entropy_test_result`)

   This event is generated each time file analysis performs
   entropy testing on a file.
   

   :param f: The file.
   

   :param ent: The results of the entropy testing.
   

.. _plugin-zeek-fileextract:

Zeek::FileExtract
-----------------

Extract file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_EXTRACT`

Events
++++++

.. zeek:id:: file_extraction_limit
   :source-code: base/files/extract/main.zeek 89 93

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`, limit: :zeek:type:`count`, len: :zeek:type:`count`)

   This event is generated when a file extraction analyzer is about
   to exceed the maximum permitted file size allowed by the
   *extract_limit* field of :zeek:see:`Files::AnalyzerArgs`.
   The analyzer is automatically removed from file *f*.
   

   :param f: The file.
   

   :param args: Arguments that identify a particular file extraction analyzer.
         This is only provided to be able to pass along to
         :zeek:see:`FileExtract::set_limit`.
   

   :param limit: The limit, in bytes, the extracted file is about to breach.
   

   :param len: The length of the file chunk about to be written.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_EXTRACT

Functions
+++++++++

.. zeek:id:: FileExtract::__set_limit
   :source-code: base/bif/plugins/Zeek_FileExtract.functions.bif.zeek 12 12

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, args: :zeek:type:`any`, n: :zeek:type:`count`) : :zeek:type:`bool`

   :zeek:see:`FileExtract::set_limit`.

.. _plugin-zeek-filehash:

Zeek::FileHash
--------------

Hash file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_MD5`

:zeek:enum:`Files::ANALYZER_SHA1`

:zeek:enum:`Files::ANALYZER_SHA224`

:zeek:enum:`Files::ANALYZER_SHA256`

:zeek:enum:`Files::ANALYZER_SHA384`

:zeek:enum:`Files::ANALYZER_SHA512`

Events
++++++

.. zeek:id:: file_hash
   :source-code: base/bif/plugins/Zeek_FileHash.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, kind: :zeek:type:`string`, hash: :zeek:type:`string`)

   This event is generated each time file analysis generates a digest of the
   file contents.
   

   :param f: The file.
   

   :param kind: The type of digest algorithm.
   

   :param hash: The result of the hashing.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_MD5
      Files::ANALYZER_SHA1 Files::ANALYZER_SHA224
      Files::ANALYZER_SHA256 Files::ANALYZER_SHA384
      Files::ANALYZER_SHA512

.. _plugin-zeek-pe:

Zeek::PE
--------

Portable Executable analyzer

Components
++++++++++

:zeek:enum:`Files::ANALYZER_PE`

Events
++++++

.. zeek:id:: pe_dos_header
   :source-code: base/files/pe/main.zeek 72 75

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::DOSHeader`)

   A :abbr:`PE (Portable Executable)` file DOS header was parsed.
   This is the top-level header and contains information like the
   size of the file, initial value of registers, etc.
   

   :param f: The file.
   

   :param h: The parsed DOS header information.
   
   .. zeek:see:: pe_dos_code pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_dos_code
   :source-code: base/bif/plugins/Zeek_PE.events.bif.zeek 25 25

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, code: :zeek:type:`string`)

   A :abbr:`PE (Portable Executable)` file DOS stub was parsed.
   The stub is a valid application that runs under MS-DOS, by default
   to inform the user that the program can't be run in DOS mode.
   

   :param f: The file.
   

   :param code: The DOS stub
   
   .. zeek:see:: pe_dos_header pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_file_header
   :source-code: base/files/pe/main.zeek 77 90

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::FileHeader`)

   A :abbr:`PE (Portable Executable)` file file header was parsed.
   This header contains information like the target machine,
   the timestamp when the file was created, the number of sections, and
   pointers to other parts of the file.
   

   :param f: The file.
   

   :param h: The parsed file header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_optional_header pe_section_header

.. zeek:id:: pe_optional_header
   :source-code: base/files/pe/main.zeek 92 119

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::OptionalHeader`)

   A :abbr:`PE (Portable Executable)` file optional header was parsed.
   This header is required for executable files, but not for object files.
   It contains information like OS requirements to execute the file, the
   original entry point address, and information needed to load the file
   into memory.
   

   :param f: The file.
   

   :param h: The parsed optional header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_section_header

.. zeek:id:: pe_section_header
   :source-code: base/files/pe/main.zeek 121 132

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::SectionHeader`)

   A :abbr:`PE (Portable Executable)` file section header was parsed.
   This header contains information like the section name, size, address,
   and characteristics.
   

   :param f: The file.
   

   :param h: The parsed section header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_optional_header

.. _plugin-zeek-x509:

Zeek::X509
----------

X509 and OCSP analyzer

Components
++++++++++

:zeek:enum:`Files::ANALYZER_OCSP_REPLY`

:zeek:enum:`Files::ANALYZER_OCSP_REQUEST`

:zeek:enum:`Files::ANALYZER_X509`

Types
+++++

.. zeek:type:: X509::Certificate
   :source-code: base/init-bare.zeek 5108 5123

   :Type: :zeek:type:`record`


   .. zeek:field:: version :zeek:type:`count` :zeek:attr:`&log`

      Version number.


   .. zeek:field:: serial :zeek:type:`string` :zeek:attr:`&log`

      Serial number.


   .. zeek:field:: subject :zeek:type:`string` :zeek:attr:`&log`

      Subject.


   .. zeek:field:: issuer :zeek:type:`string` :zeek:attr:`&log`

      Issuer.


   .. zeek:field:: cn :zeek:type:`string` :zeek:attr:`&optional`

      Last (most specific) common name.


   .. zeek:field:: not_valid_before :zeek:type:`time` :zeek:attr:`&log`

      Timestamp before when certificate is not valid.


   .. zeek:field:: not_valid_after :zeek:type:`time` :zeek:attr:`&log`

      Timestamp after when certificate is not valid.


   .. zeek:field:: key_alg :zeek:type:`string` :zeek:attr:`&log`

      Name of the key algorithm


   .. zeek:field:: sig_alg :zeek:type:`string` :zeek:attr:`&log`

      Name of the signature algorithm


   .. zeek:field:: key_type :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Key type, if key parseable by openssl (either rsa, dsa or ec)


   .. zeek:field:: key_length :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Key length in bits


   .. zeek:field:: exponent :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Exponent, if RSA-certificate


   .. zeek:field:: curve :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Curve, if EC-certificate


   .. zeek:field:: tbs_sig_alg :zeek:type:`string`

      Name of the signature algorithm given inside the tbsCertificate. Should be equivalent to `sig_alg`.



.. zeek:type:: X509::Extension
   :source-code: base/init-bare.zeek 5125 5131

   :Type: :zeek:type:`record`


   .. zeek:field:: name :zeek:type:`string`

      Long name of extension. oid if name not known


   .. zeek:field:: short_name :zeek:type:`string` :zeek:attr:`&optional`

      Short name of extension if known


   .. zeek:field:: oid :zeek:type:`string`

      Oid of extension


   .. zeek:field:: critical :zeek:type:`bool`

      True if extension is critical


   .. zeek:field:: value :zeek:type:`string`

      Extension content parsed to string for known extensions. Raw data otherwise.



.. zeek:type:: X509::BasicConstraints
   :source-code: base/init-bare.zeek 5133 5136

   :Type: :zeek:type:`record`


   .. zeek:field:: ca :zeek:type:`bool` :zeek:attr:`&log`

      CA flag set?


   .. zeek:field:: path_len :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Maximum path length

   :Attributes: :zeek:attr:`&log`


.. zeek:type:: X509::SubjectAlternativeName
   :source-code: base/init-bare.zeek 5138 5144

   :Type: :zeek:type:`record`


   .. zeek:field:: dns :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`

      List of DNS entries in SAN


   .. zeek:field:: uri :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`

      List of URI entries in SAN


   .. zeek:field:: email :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`

      List of email entries in SAN


   .. zeek:field:: ip :zeek:type:`addr_vec` :zeek:attr:`&optional` :zeek:attr:`&log`

      List of IP entries in SAN


   .. zeek:field:: other_fields :zeek:type:`bool`

      True if the certificate contained other, not recognized or parsed name fields



.. zeek:type:: X509::Result
   :source-code: base/init-bare.zeek 5147 5154

   :Type: :zeek:type:`record`


   .. zeek:field:: result :zeek:type:`int`

      OpenSSL result code


   .. zeek:field:: result_string :zeek:type:`string`

      Result as string


   .. zeek:field:: chain_certs :zeek:type:`vector` of :zeek:type:`opaque` of x509 :zeek:attr:`&optional`

      References to the final certificate chain, if verification successful. End-host certificate is first.


   Result of an X509 certificate chain verification

Events
++++++

.. zeek:id:: x509_certificate
   :source-code: base/bif/plugins/Zeek_X509.events.bif.zeek 20 20

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, cert_ref: :zeek:type:`opaque` of x509, cert: :zeek:type:`X509::Certificate`)

   Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
   connection handshake.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :param f: The file.
   

   :param cert_ref: An opaque pointer to the underlying OpenSSL data structure of the
             certificate.
   

   :param cert: The parsed certificate information.
   
   .. zeek:see:: x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_extension
   :source-code: base/files/x509/main.zeek 224 231

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::Extension`)

   Generated for X509 extensions seen in a certificate.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :param f: The file.
   

   :param ext: The parsed extension.
   
   .. zeek:see:: x509_certificate x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ext_basic_constraints
   :source-code: base/files/x509/main.zeek 233 240

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

.. zeek:id:: ocsp_request
   :source-code: base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek 16 16

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, version: :zeek:type:`count`)

   Event that is raised when encountering an OCSP request, e.g. in an HTTP
   connection. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP Request.
   

   :param f: The file.
   

   :param req: version: the version of the OCSP request. Typically 0 (Version 1).
   
   .. zeek:see:: ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_request_certificate
   :source-code: base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek 37 37

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, hashAlgorithm: :zeek:type:`string`, issuerNameHash: :zeek:type:`string`, issuerKeyHash: :zeek:type:`string`, serialNumber: :zeek:type:`string`)

   Event that is raised when encountering an OCSP request for a certificate,
   e.g. in an HTTP connection. See :rfc:`6960` for more details.
   
   Note that a single OCSP request can contain requests for several certificates.
   Thus this event can fire several times for one OCSP request, each time
   requesting information for a different (or in theory even the same) certificate.
   

   :param f: The file.
   

   :param hashAlgorithm: The hash algorithm used for the issuerKeyHash.
   

   :param issuerKeyHash: Hash of the issuers public key.
   

   :param serialNumber: Serial number of the certificate for which the status is requested.
   
   .. zeek:see:: ocsp_request ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_status
   :source-code: base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek 52 52

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, status: :zeek:type:`string`)

   This event is raised when encountering an OCSP reply, e.g. in an HTTP
   connection or a TLS extension. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP reply.
   

   :param f: The file.
   

   :param status: The status of the OCSP response (e.g. successful, malformedRequest, tryLater).
   
   .. zeek:see:: ocsp_request ocsp_request_certificate
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_bytes
   :source-code: base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek 77 77

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, status: :zeek:type:`string`, version: :zeek:type:`count`, responderId: :zeek:type:`string`, producedAt: :zeek:type:`time`, signatureAlgorithm: :zeek:type:`string`, certs: :zeek:type:`x509_opaque_vector`)

   This event is raised when encountering an OCSP response that contains response information.
   An OCSP reply can be encountered, for example, in an HTTP connection or
   a TLS extension. See :rfc:`6960` for more details on OCSP.
   

   :param f: The file.
   

   :param status: The status of the OCSP response (e.g. successful, malformedRequest, tryLater).
   

   :param version: Version of the OCSP response (typically - for version 1).
   

   :param responderId: The id of the OCSP responder; either a public key hash or a distinguished name.
   

   :param producedAt: Time at which the reply was produced.
   

   :param signatureAlgorithm: Algorithm used for the OCSP signature.
   

   :param certs: Optional list of certificates that are sent with the OCSP response; these typically
          are needed to perform validation of the reply.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_certificate
   :source-code: base/files/x509/log-ocsp.zeek 47 61

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, hashAlgorithm: :zeek:type:`string`, issuerNameHash: :zeek:type:`string`, issuerKeyHash: :zeek:type:`string`, serialNumber: :zeek:type:`string`, certStatus: :zeek:type:`string`, revokeTime: :zeek:type:`time`, revokeReason: :zeek:type:`string`, thisUpdate: :zeek:type:`time`, nextUpdate: :zeek:type:`time`)

   This event is raised for each SingleResponse contained in an OCSP response.
   See :rfc:`6960` for more details on OCSP.
   

   :param f: The file.
   

   :param hashAlgorithm: The hash algorithm used for issuerNameHash and issuerKeyHash.
   

   :param issuerNameHash: Hash of the issuer's distinguished name.
   

   :param issuerKeyHash: Hash of the issuer's public key.
   

   :param serialNumber: Serial number of the affected certificate.
   

   :param certStatus: Status of the certificate.
   

   :param revokeTime: Time the certificate was revoked, 0 if not revoked.
   

   :param revokeReason: Reason certificate was revoked; empty string if not revoked or not specified.
   

   :param thisUpdate: Time this response was generated.
   

   :param nextUpdate: Time next response will be ready; 0 if not supplied.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_extension
   :source-code: base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek 122 122

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::Extension`, global_resp: :zeek:type:`bool`)

   This event is raised when an OCSP extension is encountered in an OCSP response.
   See :rfc:`6960` for more details on OCSP.
   

   :param f: The file.
   

   :param ext: The parsed extension (same format as X.509 extensions).
   

   :param global_resp: T if extension encountered in the global response (in ResponseData),
                F when encountered in a SingleResponse.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp

Functions
+++++++++

.. zeek:id:: x509_parse
   :source-code: base/bif/plugins/Zeek_X509.functions.bif.zeek 15 15

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509) : :zeek:type:`X509::Certificate`

   Parses a certificate into an X509::Certificate structure.
   

   :param cert: The X509 certificate opaque handle.
   

   :returns: A X509::Certificate structure.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string

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

