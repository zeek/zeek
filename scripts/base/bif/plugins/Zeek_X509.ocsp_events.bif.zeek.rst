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

.. zeek:id:: ocsp_response_bytes

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, resp_ref: :zeek:type:`opaque` of ocsp_resp, status: :zeek:type:`string`, version: :zeek:type:`count`, responderId: :zeek:type:`string`, producedAt: :zeek:type:`time`, signatureAlgorithm: :zeek:type:`string`, certs: :zeek:type:`x509_opaque_vector`)

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


