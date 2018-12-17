:tocdepth: 3

base/bif/plugins/Bro_X509.ocsp_events.bif.bro
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===========================================================================================
:bro:id:`ocsp_extension`: :bro:type:`event`            This event is raised when an OCSP extension is encountered in an OCSP response.
:bro:id:`ocsp_request`: :bro:type:`event`              Event that is raised when encountering an OCSP request, e.g.
:bro:id:`ocsp_request_certificate`: :bro:type:`event`  Event that is raised when encountering an OCSP request for a certificate,
                                                       e.g.
:bro:id:`ocsp_response_bytes`: :bro:type:`event`       This event is raised when encountering an OCSP response that contains response information.
:bro:id:`ocsp_response_certificate`: :bro:type:`event` This event is raised for each SingleResponse contained in an OCSP response.
:bro:id:`ocsp_response_status`: :bro:type:`event`      This event is raised when encountering an OCSP reply, e.g.
====================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
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


