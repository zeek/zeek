File Analyzers
==============

.. zeek:type:: Files::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Files::ANALYZER_DATA_EVENT Files::Tag

      .. zeek:enum:: Files::ANALYZER_ENTROPY Files::Tag

      .. zeek:enum:: Files::ANALYZER_EXTRACT Files::Tag

      .. zeek:enum:: Files::ANALYZER_MD5 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA1 Files::Tag

      .. zeek:enum:: Files::ANALYZER_SHA256 Files::Tag

      .. zeek:enum:: Files::ANALYZER_PE Files::Tag

      .. zeek:enum:: Files::ANALYZER_UNIFIED2 Files::Tag

      .. zeek:enum:: Files::ANALYZER_OCSP_REPLY Files::Tag

      .. zeek:enum:: Files::ANALYZER_OCSP_REQUEST Files::Tag

      .. zeek:enum:: Files::ANALYZER_X509 Files::Tag

Zeek::FileDataEvent
-------------------

Delivers file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_DATA_EVENT`

Zeek::FileEntropy
-----------------

Entropy test file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_ENTROPY`

Events
++++++

.. zeek:id:: file_entropy

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ent: :zeek:type:`entropy_test_result`)

   This event is generated each time file analysis performs
   entropy testing on a file.
   

   :f: The file.
   

   :ent: The results of the entropy testing.
   

Zeek::FileExtract
-----------------

Extract file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_EXTRACT`

Events
++++++

.. zeek:id:: file_extraction_limit

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`, limit: :zeek:type:`count`, len: :zeek:type:`count`)

   This event is generated when a file extraction analyzer is about
   to exceed the maximum permitted file size allowed by the
   *extract_limit* field of :zeek:see:`Files::AnalyzerArgs`.
   The analyzer is automatically removed from file *f*.
   

   :f: The file.
   

   :args: Arguments that identify a particular file extraction analyzer.
         This is only provided to be able to pass along to
         :zeek:see:`FileExtract::set_limit`.
   

   :limit: The limit, in bytes, the extracted file is about to breach.
   

   :len: The length of the file chunk about to be written.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_EXTRACT

Functions
+++++++++

.. zeek:id:: FileExtract::__set_limit

   :Type: :zeek:type:`function` (file_id: :zeek:type:`string`, args: :zeek:type:`any`, n: :zeek:type:`count`) : :zeek:type:`bool`

   :zeek:see:`FileExtract::set_limit`.

Zeek::FileHash
--------------

Hash file content

Components
++++++++++

:zeek:enum:`Files::ANALYZER_MD5`

:zeek:enum:`Files::ANALYZER_SHA1`

:zeek:enum:`Files::ANALYZER_SHA256`

Events
++++++

.. zeek:id:: file_hash

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, kind: :zeek:type:`string`, hash: :zeek:type:`string`)

   This event is generated each time file analysis generates a digest of the
   file contents.
   

   :f: The file.
   

   :kind: The type of digest algorithm.
   

   :hash: The result of the hashing.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_MD5
      Files::ANALYZER_SHA1 Files::ANALYZER_SHA256

Zeek::PE
--------

Portable Executable analyzer

Components
++++++++++

:zeek:enum:`Files::ANALYZER_PE`

Events
++++++

.. zeek:id:: pe_dos_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::DOSHeader`)

   A :abbr:`PE (Portable Executable)` file DOS header was parsed.
   This is the top-level header and contains information like the
   size of the file, initial value of registers, etc.
   

   :f: The file.
   

   :h: The parsed DOS header information.
   
   .. zeek:see:: pe_dos_code pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_dos_code

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, code: :zeek:type:`string`)

   A :abbr:`PE (Portable Executable)` file DOS stub was parsed.
   The stub is a valid application that runs under MS-DOS, by default
   to inform the user that the program can't be run in DOS mode.
   

   :f: The file.
   

   :code: The DOS stub
   
   .. zeek:see:: pe_dos_header pe_file_header pe_optional_header pe_section_header

.. zeek:id:: pe_file_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::FileHeader`)

   A :abbr:`PE (Portable Executable)` file file header was parsed.
   This header contains information like the target machine,
   the timestamp when the file was created, the number of sections, and
   pointers to other parts of the file.
   

   :f: The file.
   

   :h: The parsed file header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_optional_header pe_section_header

.. zeek:id:: pe_optional_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::OptionalHeader`)

   A :abbr:`PE (Portable Executable)` file optional header was parsed.
   This header is required for executable files, but not for object files.
   It contains information like OS requirements to execute the file, the
   original entry point address, and information needed to load the file
   into memory.
   

   :f: The file.
   

   :h: The parsed optional header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_section_header

.. zeek:id:: pe_section_header

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, h: :zeek:type:`PE::SectionHeader`)

   A :abbr:`PE (Portable Executable)` file section header was parsed.
   This header contains information like the section name, size, address,
   and characteristics.
   

   :f: The file.
   

   :h: The parsed section header information.
   
   .. zeek:see:: pe_dos_header pe_dos_code pe_file_header pe_optional_header

Zeek::Unified2
--------------

Analyze Unified2 alert files.

Components
++++++++++

:zeek:enum:`Files::ANALYZER_UNIFIED2`

Types
+++++

.. zeek:type:: Unified2::IDSEvent

   :Type: :zeek:type:`record`

      sensor_id: :zeek:type:`count`

      event_id: :zeek:type:`count`

      ts: :zeek:type:`time`

      signature_id: :zeek:type:`count`

      generator_id: :zeek:type:`count`

      signature_revision: :zeek:type:`count`

      classification_id: :zeek:type:`count`

      priority_id: :zeek:type:`count`

      src_ip: :zeek:type:`addr`

      dst_ip: :zeek:type:`addr`

      src_p: :zeek:type:`port`

      dst_p: :zeek:type:`port`

      impact_flag: :zeek:type:`count`

      impact: :zeek:type:`count`

      blocked: :zeek:type:`count`

      mpls_label: :zeek:type:`count` :zeek:attr:`&optional`
         Not available in "legacy" IDS events.

      vlan_id: :zeek:type:`count` :zeek:attr:`&optional`
         Not available in "legacy" IDS events.

      packet_action: :zeek:type:`count` :zeek:attr:`&optional`
         Only available in "legacy" IDS events.


.. zeek:type:: Unified2::Packet

   :Type: :zeek:type:`record`

      sensor_id: :zeek:type:`count`

      event_id: :zeek:type:`count`

      event_second: :zeek:type:`count`

      packet_ts: :zeek:type:`time`

      link_type: :zeek:type:`count`

      data: :zeek:type:`string`


Events
++++++

.. zeek:id:: unified2_event

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ev: :zeek:type:`Unified2::IDSEvent`)

   Abstract all of the various Unified2 event formats into 
   a single event.
   

   :f: The file.
   

   :ev: TODO.
   

.. zeek:id:: unified2_packet

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, pkt: :zeek:type:`Unified2::Packet`)

   The Unified2 packet format event.
   

   :f: The file.
   

   :pkt: TODO.
   

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

   :Type: :zeek:type:`record`

      version: :zeek:type:`count` :zeek:attr:`&log`
         Version number.

      serial: :zeek:type:`string` :zeek:attr:`&log`
         Serial number.

      subject: :zeek:type:`string` :zeek:attr:`&log`
         Subject.

      issuer: :zeek:type:`string` :zeek:attr:`&log`
         Issuer.

      cn: :zeek:type:`string` :zeek:attr:`&optional`
         Last (most specific) common name.

      not_valid_before: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp before when certificate is not valid.

      not_valid_after: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp after when certificate is not valid.

      key_alg: :zeek:type:`string` :zeek:attr:`&log`
         Name of the key algorithm

      sig_alg: :zeek:type:`string` :zeek:attr:`&log`
         Name of the signature algorithm

      key_type: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Key type, if key parseable by openssl (either rsa, dsa or ec)

      key_length: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Key length in bits

      exponent: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Exponent, if RSA-certificate

      curve: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Curve, if EC-certificate


.. zeek:type:: X509::Extension

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Long name of extension. oid if name not known

      short_name: :zeek:type:`string` :zeek:attr:`&optional`
         Short name of extension if known

      oid: :zeek:type:`string`
         Oid of extension

      critical: :zeek:type:`bool`
         True if extension is critical

      value: :zeek:type:`string`
         Extension content parsed to string for known extensions. Raw data otherwise.


.. zeek:type:: X509::BasicConstraints

   :Type: :zeek:type:`record`

      ca: :zeek:type:`bool` :zeek:attr:`&log`
         CA flag set?

      path_len: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Maximum path length
   :Attributes: :zeek:attr:`&log`


.. zeek:type:: X509::SubjectAlternativeName

   :Type: :zeek:type:`record`

      dns: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of DNS entries in SAN

      uri: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of URI entries in SAN

      email: :zeek:type:`string_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of email entries in SAN

      ip: :zeek:type:`addr_vec` :zeek:attr:`&optional` :zeek:attr:`&log`
         List of IP entries in SAN

      other_fields: :zeek:type:`bool`
         True if the certificate contained other, not recognized or parsed name fields


.. zeek:type:: X509::Result

   :Type: :zeek:type:`record`

      result: :zeek:type:`int`
         OpenSSL result code

      result_string: :zeek:type:`string`
         Result as string

      chain_certs: :zeek:type:`vector` of :zeek:type:`opaque` of x509 :zeek:attr:`&optional`
         References to the final certificate chain, if verification successful. End-host certificate is first.

   Result of an X509 certificate chain verification

Events
++++++

.. zeek:id:: x509_certificate

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, cert_ref: :zeek:type:`opaque` of x509, cert: :zeek:type:`X509::Certificate`)

   Generated for encountered X509 certificates, e.g., in the clear SSL/TLS
   connection handshake.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :f: The file.
   

   :cert_ref: An opaque pointer to the underlying OpenSSL data structure of the
             certificate.
   

   :cert: The parsed certificate information.
   
   .. zeek:see:: x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_extension

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::Extension`)

   Generated for X509 extensions seen in a certificate.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/X.509>`__ for more information
   about the X.509 format.
   

   :f: The file.
   

   :ext: The parsed extension.
   
   .. zeek:see:: x509_certificate x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ext_basic_constraints

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::BasicConstraints`)

   Generated for the X509 basic constraints extension seen in a certificate.
   This extension can be used to identify the subject of a certificate as a CA.
   

   :f: The file.
   

   :ext: The parsed basic constraints extension.
   
   .. zeek:see:: x509_certificate x509_extension
                x509_ext_subject_alternative_name x509_parse x509_verify
                x509_get_certificate_string x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: x509_ext_subject_alternative_name

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::SubjectAlternativeName`)

   Generated for the X509 subject alternative name extension seen in a certificate.
   This extension can be used to allow additional entities to be bound to the
   subject of the certificate. Usually it is used to specify one or multiple DNS
   names for which a certificate is valid.
   

   :f: The file.
   

   :ext: The parsed subject alternative name extension.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ocsp_ext_signed_certificate_timestamp
                x509_get_certificate_string

.. zeek:id:: x509_ocsp_ext_signed_certificate_timestamp

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, version: :zeek:type:`count`, logid: :zeek:type:`string`, timestamp: :zeek:type:`count`, hash_algorithm: :zeek:type:`count`, signature_algorithm: :zeek:type:`count`, signature: :zeek:type:`string`)

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
   
   .. zeek:see:: ssl_extension_signed_certificate_timestamp x509_extension x509_ext_basic_constraints
                x509_parse x509_verify x509_ext_subject_alternative_name
                x509_get_certificate_string ssl_extension_signed_certificate_timestamp
                sct_verify ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_request

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, version: :zeek:type:`count`)

   Event that is raised when encountering an OCSP request, e.g. in an HTTP
   connection. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP Request.
   

   :f: The file.
   

   :req: version: the version of the OCSP request. Typically 0 (Version 1).
   
   .. zeek:see:: ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_request_certificate

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, hashAlgorithm: :zeek:type:`string`, issuerNameHash: :zeek:type:`string`, issuerKeyHash: :zeek:type:`string`, serialNumber: :zeek:type:`string`)

   Event that is raised when encountering an OCSP request for a certificate,
   e.g. in an HTTP connection. See :rfc:`6960` for more details.
   
   Note that a single OCSP request can contain requests for several certificates.
   Thus this event can fire several times for one OCSP request, each time
   requesting information for a different (or in theory even the same) certificate.
   

   :f: The file.
   

   :hashAlgorithm: The hash algorithm used for the issuerKeyHash.
   

   :issuerKeyHash: Hash of the issuers public key.
   

   :serialNumber: Serial number of the certificate for which the status is requested.
   
   .. zeek:see:: ocsp_request ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_status

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, status: :zeek:type:`string`)

   This event is raised when encountering an OCSP reply, e.g. in an HTTP
   connection or a TLS extension. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP reply.
   

   :f: The file.
   

   :status: The status of the OCSP response (e.g. succesful, malformedRequest, tryLater).
   
   .. zeek:see:: ocsp_request ocsp_request_certificate
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_bytes

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, status: :zeek:type:`string`, version: :zeek:type:`count`, responderId: :zeek:type:`string`, producedAt: :zeek:type:`time`, signatureAlgorithm: :zeek:type:`string`, certs: :zeek:type:`x509_opaque_vector`)

   This event is raised when encountering an OCSP response that contains response information.
   An OCSP reply can be encountered, for example, in an HTTP connection or
   a TLS extension. See :rfc:`6960` for more details on OCSP.
   

   :f: The file.
   

   :status: The status of the OCSP response (e.g. succesful, malformedRequest, tryLater).
   

   :version: Version of the OCSP response (typically - for version 1).
   

   :responderId: The id of the OCSP responder; either a public key hash or a distinguished name.
   

   :producedAt: Time at which the reply was produced.
   

   :signatureAlgorithm: Algorithm used for the OCSP signature.
   

   :certs: Optional list of certificates that are sent with the OCSP response; these typically
          are needed to perform validation of the reply.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_response_certificate

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, hashAlgorithm: :zeek:type:`string`, issuerNameHash: :zeek:type:`string`, issuerKeyHash: :zeek:type:`string`, serialNumber: :zeek:type:`string`, certStatus: :zeek:type:`string`, revokeTime: :zeek:type:`time`, revokeReason: :zeek:type:`string`, thisUpdate: :zeek:type:`time`, nextUpdate: :zeek:type:`time`)

   This event is raised for each SingleResponse contained in an OCSP response.
   See :rfc:`6960` for more details on OCSP.
   

   :f: The file.
   

   :hashAlgorithm: The hash algorithm used for issuerNameHash and issuerKeyHash.
   

   :issuerNameHash: Hash of the issuer's distinguished name.
   

   :issuerKeyHash: Hash of the issuer's public key.
   

   :serialNumber: Serial number of the affected certificate.
   

   :certStatus: Status of the certificate.
   

   :revokeTime: Time the certificate was revoked, 0 if not revoked.
   

   :revokeTeason: Reason certificate was revoked; empty string if not revoked or not specified.
   

   :thisUpdate: Time this response was generated.
   

   :nextUpdate: Time next response will be ready; 0 if not supploed.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. zeek:id:: ocsp_extension

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ext: :zeek:type:`X509::Extension`, global_resp: :zeek:type:`bool`)

   This event is raised when an OCSP extension is encountered in an OCSP response.
   See :rfc:`6960` for more details on OCSP.
   

   :f: The file.
   

   :ext: The parsed extension (same format as X.509 extensions).
   

   :global_resp: T if extension encountered in the global response (in ResponseData),
                F when encountered in a SingleResponse.
   
   .. zeek:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp

Functions
+++++++++

.. zeek:id:: x509_parse

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509) : :zeek:type:`X509::Certificate`

   Parses a certificate into an X509::Certificate structure.
   

   :cert: The X509 certificate opaque handle.
   

   :returns: A X509::Certificate structure.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string

.. zeek:id:: x509_from_der

   :Type: :zeek:type:`function` (der: :zeek:type:`string`) : :zeek:type:`opaque` of x509

   Constructs an opaque of X509 from a der-formatted string.
   

   :Note: this function is mostly meant for testing purposes
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string x509_parse

.. zeek:id:: x509_get_certificate_string

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, pem: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns the string form of a certificate.
   

   :cert: The X509 certificate opaque handle.
   

   :pem: A boolean that specifies if the certificate is returned
        in pem-form (true), or as the raw ASN1 encoded binary
        (false).
   

   :returns: X509 certificate as a string.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse x509_verify

.. zeek:id:: x509_ocsp_verify

   :Type: :zeek:type:`function` (certs: :zeek:type:`x509_opaque_vector`, ocsp_reply: :zeek:type:`string`, root_certs: :zeek:type:`table_string_of_string`, verify_time: :zeek:type:`time` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`) : :zeek:type:`X509::Result`

   Verifies an OCSP reply.
   

   :certs: Specifies the certificate chain to use. Server certificate first.
   

   :ocsp_reply: the ocsp reply to validate.
   

   :root_certs: A list of root certificates to validate the certificate chain.
   

   :verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_verify

.. zeek:id:: x509_verify

   :Type: :zeek:type:`function` (certs: :zeek:type:`x509_opaque_vector`, root_certs: :zeek:type:`table_string_of_string`, verify_time: :zeek:type:`time` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`) : :zeek:type:`X509::Result`

   Verifies a certificate.
   

   :certs: Specifies a certificate chain that is being used to validate
          the given certificate against the root store given in *root_certs*.
          The host certificate has to be at index 0.
   

   :root_certs: A list of root certificates to validate the certificate chain.
   

   :verify_time: Time for the validity check of the certificates.
   

   :returns: A record of type X509::Result containing the result code of the
            verify operation. In case of success also returns the full
            certificate chain.
   
   .. zeek:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_parse
                x509_get_certificate_string x509_ocsp_verify sct_verify

.. zeek:id:: sct_verify

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, logid: :zeek:type:`string`, log_key: :zeek:type:`string`, signature: :zeek:type:`string`, timestamp: :zeek:type:`count`, hash_algorithm: :zeek:type:`count`, issuer_key_hash: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

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
   
   .. zeek:see:: ssl_extension_signed_certificate_timestamp
                x509_ocsp_ext_signed_certificate_timestamp
                x509_verify

.. zeek:id:: x509_subject_name_hash

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the subject's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_issuer_name_hash x509_spki_hash
                x509_verify sct_verify

.. zeek:id:: x509_issuer_name_hash

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the issuer's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_subject_name_hash x509_spki_hash
                x509_verify sct_verify

.. zeek:id:: x509_spki_hash

   :Type: :zeek:type:`function` (cert: :zeek:type:`opaque` of x509, hash_alg: :zeek:type:`count`) : :zeek:type:`string`

   Get the hash of the Subject Public Key Information of the certificate.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. zeek:see:: x509_subject_name_hash x509_issuer_name_hash
                x509_verify sct_verify

