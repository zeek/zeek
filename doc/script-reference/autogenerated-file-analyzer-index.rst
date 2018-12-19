File Analyzers
==============

.. bro:type:: Files::Tag

   :Type: :bro:type:`enum`

      .. bro:enum:: Files::ANALYZER_DATA_EVENT Files::Tag

      .. bro:enum:: Files::ANALYZER_ENTROPY Files::Tag

      .. bro:enum:: Files::ANALYZER_EXTRACT Files::Tag

      .. bro:enum:: Files::ANALYZER_MD5 Files::Tag

      .. bro:enum:: Files::ANALYZER_SHA1 Files::Tag

      .. bro:enum:: Files::ANALYZER_SHA256 Files::Tag

      .. bro:enum:: Files::ANALYZER_PE Files::Tag

      .. bro:enum:: Files::ANALYZER_UNIFIED2 Files::Tag

      .. bro:enum:: Files::ANALYZER_OCSP_REPLY Files::Tag

      .. bro:enum:: Files::ANALYZER_OCSP_REQUEST Files::Tag

      .. bro:enum:: Files::ANALYZER_X509 Files::Tag

Bro::FileDataEvent
------------------

Delivers file content

Components
++++++++++

:bro:enum:`Files::ANALYZER_DATA_EVENT`

Bro::FileEntropy
----------------

Entropy test file content

Components
++++++++++

:bro:enum:`Files::ANALYZER_ENTROPY`

Events
++++++

.. bro:id:: file_entropy

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ent: :bro:type:`entropy_test_result`)

   This event is generated each time file analysis performs
   entropy testing on a file.
   

   :f: The file.
   

   :ent: The results of the entropy testing.
   

Bro::FileExtract
----------------

Extract file content

Components
++++++++++

:bro:enum:`Files::ANALYZER_EXTRACT`

Events
++++++

.. bro:id:: file_extraction_limit

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, args: :bro:type:`Files::AnalyzerArgs`, limit: :bro:type:`count`, len: :bro:type:`count`)

   This event is generated when a file extraction analyzer is about
   to exceed the maximum permitted file size allowed by the
   *extract_limit* field of :bro:see:`Files::AnalyzerArgs`.
   The analyzer is automatically removed from file *f*.
   

   :f: The file.
   

   :args: Arguments that identify a particular file extraction analyzer.
         This is only provided to be able to pass along to
         :bro:see:`FileExtract::set_limit`.
   

   :limit: The limit, in bytes, the extracted file is about to breach.
   

   :len: The length of the file chunk about to be written.
   
   .. bro:see:: Files::add_analyzer Files::ANALYZER_EXTRACT

Functions
+++++++++

.. bro:id:: FileExtract::__set_limit

   :Type: :bro:type:`function` (file_id: :bro:type:`string`, args: :bro:type:`any`, n: :bro:type:`count`) : :bro:type:`bool`

   :bro:see:`FileExtract::set_limit`.

Bro::FileHash
-------------

Hash file content

Components
++++++++++

:bro:enum:`Files::ANALYZER_MD5`

:bro:enum:`Files::ANALYZER_SHA1`

:bro:enum:`Files::ANALYZER_SHA256`

Events
++++++

.. bro:id:: file_hash

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, kind: :bro:type:`string`, hash: :bro:type:`string`)

   This event is generated each time file analysis generates a digest of the
   file contents.
   

   :f: The file.
   

   :kind: The type of digest algorithm.
   

   :hash: The result of the hashing.
   
   .. bro:see:: Files::add_analyzer Files::ANALYZER_MD5
      Files::ANALYZER_SHA1 Files::ANALYZER_SHA256

Bro::PE
-------

Portable Executable analyzer

Components
++++++++++

:bro:enum:`Files::ANALYZER_PE`

Events
++++++

.. bro:id:: pe_dos_header

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, h: :bro:type:`PE::DOSHeader`)

   A :abbr:`PE (Portable Executable)` file DOS header was parsed.
   This is the top-level header and contains information like the
   size of the file, initial value of registers, etc.
   

   :f: The file.
   

   :h: The parsed DOS header information.
   
   .. bro:see:: pe_dos_code pe_file_header pe_optional_header pe_section_header

.. bro:id:: pe_dos_code

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, code: :bro:type:`string`)

   A :abbr:`PE (Portable Executable)` file DOS stub was parsed.
   The stub is a valid application that runs under MS-DOS, by default
   to inform the user that the program can't be run in DOS mode.
   

   :f: The file.
   

   :code: The DOS stub
   
   .. bro:see:: pe_dos_header pe_file_header pe_optional_header pe_section_header

.. bro:id:: pe_file_header

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, h: :bro:type:`PE::FileHeader`)

   A :abbr:`PE (Portable Executable)` file file header was parsed.
   This header contains information like the target machine,
   the timestamp when the file was created, the number of sections, and
   pointers to other parts of the file.
   

   :f: The file.
   

   :h: The parsed file header information.
   
   .. bro:see:: pe_dos_header pe_dos_code pe_optional_header pe_section_header

.. bro:id:: pe_optional_header

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, h: :bro:type:`PE::OptionalHeader`)

   A :abbr:`PE (Portable Executable)` file optional header was parsed.
   This header is required for executable files, but not for object files.
   It contains information like OS requirements to execute the file, the
   original entry point address, and information needed to load the file
   into memory.
   

   :f: The file.
   

   :h: The parsed optional header information.
   
   .. bro:see:: pe_dos_header pe_dos_code pe_file_header pe_section_header

.. bro:id:: pe_section_header

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, h: :bro:type:`PE::SectionHeader`)

   A :abbr:`PE (Portable Executable)` file section header was parsed.
   This header contains information like the section name, size, address,
   and characteristics.
   

   :f: The file.
   

   :h: The parsed section header information.
   
   .. bro:see:: pe_dos_header pe_dos_code pe_file_header pe_optional_header

Bro::Unified2
-------------

Analyze Unified2 alert files.

Components
++++++++++

:bro:enum:`Files::ANALYZER_UNIFIED2`

Types
+++++

.. bro:type:: Unified2::IDSEvent

   :Type: :bro:type:`record`

      sensor_id: :bro:type:`count`

      event_id: :bro:type:`count`

      ts: :bro:type:`time`

      signature_id: :bro:type:`count`

      generator_id: :bro:type:`count`

      signature_revision: :bro:type:`count`

      classification_id: :bro:type:`count`

      priority_id: :bro:type:`count`

      src_ip: :bro:type:`addr`

      dst_ip: :bro:type:`addr`

      src_p: :bro:type:`port`

      dst_p: :bro:type:`port`

      impact_flag: :bro:type:`count`

      impact: :bro:type:`count`

      blocked: :bro:type:`count`

      mpls_label: :bro:type:`count` :bro:attr:`&optional`
         Not available in "legacy" IDS events.

      vlan_id: :bro:type:`count` :bro:attr:`&optional`
         Not available in "legacy" IDS events.

      packet_action: :bro:type:`count` :bro:attr:`&optional`
         Only available in "legacy" IDS events.


.. bro:type:: Unified2::Packet

   :Type: :bro:type:`record`

      sensor_id: :bro:type:`count`

      event_id: :bro:type:`count`

      event_second: :bro:type:`count`

      packet_ts: :bro:type:`time`

      link_type: :bro:type:`count`

      data: :bro:type:`string`


Events
++++++

.. bro:id:: unified2_event

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ev: :bro:type:`Unified2::IDSEvent`)

   Abstract all of the various Unified2 event formats into 
   a single event.
   

   :f: The file.
   

   :ev: TODO.
   

.. bro:id:: unified2_packet

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, pkt: :bro:type:`Unified2::Packet`)

   The Unified2 packet format event.
   

   :f: The file.
   

   :pkt: TODO.
   

Bro::X509
---------

X509 and OCSP analyzer

Components
++++++++++

:bro:enum:`Files::ANALYZER_OCSP_REPLY`

:bro:enum:`Files::ANALYZER_OCSP_REQUEST`

:bro:enum:`Files::ANALYZER_X509`

Types
+++++

.. bro:type:: X509::Certificate

   :Type: :bro:type:`record`

      version: :bro:type:`count` :bro:attr:`&log`
         Version number.

      serial: :bro:type:`string` :bro:attr:`&log`
         Serial number.

      subject: :bro:type:`string` :bro:attr:`&log`
         Subject.

      issuer: :bro:type:`string` :bro:attr:`&log`
         Issuer.

      cn: :bro:type:`string` :bro:attr:`&optional`
         Last (most specific) common name.

      not_valid_before: :bro:type:`time` :bro:attr:`&log`
         Timestamp before when certificate is not valid.

      not_valid_after: :bro:type:`time` :bro:attr:`&log`
         Timestamp after when certificate is not valid.

      key_alg: :bro:type:`string` :bro:attr:`&log`
         Name of the key algorithm

      sig_alg: :bro:type:`string` :bro:attr:`&log`
         Name of the signature algorithm

      key_type: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Key type, if key parseable by openssl (either rsa, dsa or ec)

      key_length: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Key length in bits

      exponent: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Exponent, if RSA-certificate

      curve: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Curve, if EC-certificate


.. bro:type:: X509::Extension

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         Long name of extension. oid if name not known

      short_name: :bro:type:`string` :bro:attr:`&optional`
         Short name of extension if known

      oid: :bro:type:`string`
         Oid of extension

      critical: :bro:type:`bool`
         True if extension is critical

      value: :bro:type:`string`
         Extension content parsed to string for known extensions. Raw data otherwise.


.. bro:type:: X509::BasicConstraints

   :Type: :bro:type:`record`

      ca: :bro:type:`bool` :bro:attr:`&log`
         CA flag set?

      path_len: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Maximum path length
   :Attributes: :bro:attr:`&log`


.. bro:type:: X509::SubjectAlternativeName

   :Type: :bro:type:`record`

      dns: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of DNS entries in SAN

      uri: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of URI entries in SAN

      email: :bro:type:`string_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of email entries in SAN

      ip: :bro:type:`addr_vec` :bro:attr:`&optional` :bro:attr:`&log`
         List of IP entries in SAN

      other_fields: :bro:type:`bool`
         True if the certificate contained other, not recognized or parsed name fields


.. bro:type:: X509::Result

   :Type: :bro:type:`record`

      result: :bro:type:`int`
         OpenSSL result code

      result_string: :bro:type:`string`
         Result as string

      chain_certs: :bro:type:`vector` of :bro:type:`opaque` of x509 :bro:attr:`&optional`
         References to the final certificate chain, if verification successful. End-host certificate is first.

   Result of an X509 certificate chain verification

Events
++++++

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

.. bro:id:: ocsp_request

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, version: :bro:type:`count`)

   Event that is raised when encountering an OCSP request, e.g. in an HTTP
   connection. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP Request.
   

   :f: The file.
   

   :req: version: the version of the OCSP request. Typically 0 (Version 1).
   
   .. bro:see:: ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: ocsp_request_certificate

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, hashAlgorithm: :bro:type:`string`, issuerNameHash: :bro:type:`string`, issuerKeyHash: :bro:type:`string`, serialNumber: :bro:type:`string`)

   Event that is raised when encountering an OCSP request for a certificate,
   e.g. in an HTTP connection. See :rfc:`6960` for more details.
   
   Note that a single OCSP request can contain requests for several certificates.
   Thus this event can fire several times for one OCSP request, each time
   requesting information for a different (or in theory even the same) certificate.
   

   :f: The file.
   

   :hashAlgorithm: The hash algorithm used for the issuerKeyHash.
   

   :issuerKeyHash: Hash of the issuers public key.
   

   :serialNumber: Serial number of the certificate for which the status is requested.
   
   .. bro:see:: ocsp_request ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: ocsp_response_status

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, status: :bro:type:`string`)

   This event is raised when encountering an OCSP reply, e.g. in an HTTP
   connection or a TLS extension. See :rfc:`6960` for more details.
   
   This event is raised exactly once for each OCSP reply.
   

   :f: The file.
   

   :status: The status of the OCSP response (e.g. succesful, malformedRequest, tryLater).
   
   .. bro:see:: ocsp_request ocsp_request_certificate
                ocsp_response_bytes ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: ocsp_response_bytes

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, resp_ref: :bro:type:`opaque` of ocsp_resp, status: :bro:type:`string`, version: :bro:type:`count`, responderId: :bro:type:`string`, producedAt: :bro:type:`time`, signatureAlgorithm: :bro:type:`string`, certs: :bro:type:`x509_opaque_vector`)

   This event is raised when encountering an OCSP response that contains response information.
   An OCSP reply can be encountered, for example, in an HTTP connection or
   a TLS extension. See :rfc:`6960` for more details on OCSP.
   

   :f: The file.
   

   :req_ref: An opaque pointer to the underlying OpenSSL data structure of the
            OCSP response.
   

   :status: The status of the OCSP response (e.g. succesful, malformedRequest, tryLater).
   

   :version: Version of the OCSP response (typically - for version 1).
   

   :responderId: The id of the OCSP responder; either a public key hash or a distinguished name.
   

   :producedAt: Time at which the reply was produced.
   

   :signatureAlgorithm: Algorithm used for the OCSP signature.
   

   :certs: Optional list of certificates that are sent with the OCSP response; these typically
          are needed to perform validation of the reply.
   
   .. bro:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_certificate ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: ocsp_response_certificate

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, hashAlgorithm: :bro:type:`string`, issuerNameHash: :bro:type:`string`, issuerKeyHash: :bro:type:`string`, serialNumber: :bro:type:`string`, certStatus: :bro:type:`string`, revokeTime: :bro:type:`time`, revokeReason: :bro:type:`string`, thisUpdate: :bro:type:`time`, nextUpdate: :bro:type:`time`)

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
   
   .. bro:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_extension
                x509_ocsp_ext_signed_certificate_timestamp

.. bro:id:: ocsp_extension

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ext: :bro:type:`X509::Extension`, global_resp: :bro:type:`bool`)

   This event is raised when an OCSP extension is encountered in an OCSP response.
   See :rfc:`6960` for more details on OCSP.
   

   :f: The file.
   

   :ext: The parsed extension (same format as X.509 extensions).
   

   :global_resp: T if extension encountered in the global response (in ResponseData),
                F when encountered in a SingleResponse.
   
   .. bro:see:: ocsp_request ocsp_request_certificate ocsp_response_status
                ocsp_response_bytes ocsp_response_certificate
                x509_ocsp_ext_signed_certificate_timestamp

Functions
+++++++++

.. bro:id:: x509_parse

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509) : :bro:type:`X509::Certificate`

   Parses a certificate into an X509::Certificate structure.
   

   :cert: The X509 certificate opaque handle.
   

   :returns: A X509::Certificate structure.
   
   .. bro:see:: x509_certificate x509_extension x509_ext_basic_constraints
                x509_ext_subject_alternative_name x509_verify
                x509_get_certificate_string

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

.. bro:id:: x509_subject_name_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the subject's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_issuer_name_hash x509_spki_hash
                x509_verify sct_verify

.. bro:id:: x509_issuer_name_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the issuer's distinguished name.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_subject_name_hash x509_spki_hash
                x509_verify sct_verify

.. bro:id:: x509_spki_hash

   :Type: :bro:type:`function` (cert: :bro:type:`opaque` of x509, hash_alg: :bro:type:`count`) : :bro:type:`string`

   Get the hash of the Subject Public Key Information of the certificate.
   

   :cert: The X509 certificate opaque handle.
   

   :hash_alg: the hash algorithm to use, according to the IANA mapping at

             :https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
   

   :returns: The hash as a string.
   
   .. bro:see:: x509_subject_name_hash x509_issuer_name_hash
                x509_verify sct_verify

