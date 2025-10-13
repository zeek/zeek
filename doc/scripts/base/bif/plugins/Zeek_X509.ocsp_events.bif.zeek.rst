:tocdepth: 3

base/bif/plugins/Zeek_X509.ocsp_events.bif.zeek
===============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ===========================================================================================
:zeek:id:`ocsp_extension`: :zeek:type:`event`            This event is raised when an OCSP extension is encountered in an OCSP response.
:zeek:id:`ocsp_request`: :zeek:type:`event`              Event that is raised when encountering an OCSP request, e.g.
:zeek:id:`ocsp_request_certificate`: :zeek:type:`event`  Event that is raised when encountering an OCSP request for a certificate,
                                                         e.g.
:zeek:id:`ocsp_response_bytes`: :zeek:type:`event`       This event is raised when encountering an OCSP response that contains response information.
:zeek:id:`ocsp_response_certificate`: :zeek:type:`event` This event is raised for each SingleResponse contained in an OCSP response.
:zeek:id:`ocsp_response_status`: :zeek:type:`event`      This event is raised when encountering an OCSP reply, e.g.
======================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
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


