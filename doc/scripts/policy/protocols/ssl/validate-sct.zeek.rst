:tocdepth: 3

policy/protocols/ssl/validate-sct.zeek
======================================
.. zeek:namespace:: SSL

Perform validation of Signed Certificate Timestamps, as used
for Certificate Transparency. See RFC6962 for more details.

:Namespace: SSL
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`policy/protocols/ssl/validate-certs.zeek </scripts/policy/protocols/ssl/validate-certs.zeek>`

Summary
~~~~~~~
Types
#####
============================================== ================================================================
:zeek:type:`SSL::SctInfo`: :zeek:type:`record` This record is used to store information about the SCTs that are
                                               encountered in a SSL connection.
:zeek:type:`SSL::SctSource`: :zeek:type:`enum` List of the different sources for Signed Certificate Timestamp
============================================== ================================================================

Redefinitions
#############
============================================================================ ===================================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record`                                  
                                                                             
                                                                             :New Fields: :zeek:type:`SSL::Info`
                                                                             
                                                                               valid_scts: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                 Number of valid SCTs that were encountered in the connection.
                                                                             
                                                                               invalid_scts: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                 Number of SCTs that could not be validated that were encountered in the connection.
                                                                             
                                                                               valid_ct_logs: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                                 Number of different Logs for which valid SCTs were encountered in the connection.
                                                                             
                                                                               valid_ct_operators: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                                 Number of different Log operators of which valid SCTs were encountered in the connection.
                                                                             
                                                                               valid_ct_operators_list: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`
                                                                                 List of operators for which valid SCTs were encountered in the connection.
                                                                             
                                                                               ct_proofs: :zeek:type:`vector` of :zeek:type:`SSL::SctInfo` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                                                 Information about all SCTs that were encountered in the connection.
:zeek:id:`SSL::ssl_store_valid_chain`: :zeek:type:`bool` :zeek:attr:`&redef` 
============================================================================ ===================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: SSL::SctInfo
   :source-code: policy/protocols/ssl/validate-sct.zeek 30 50

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The version of the encountered SCT (should always be 0 for v1).

      logid: :zeek:type:`string`
         The ID of the log issuing this SCT.

      timestamp: :zeek:type:`count`
         The timestamp at which this SCT was issued measured since the
         epoch (January 1, 1970, 00:00), ignoring leap seconds, in
         milliseconds. Not converted to a Zeek timestamp because we need
         the exact value for validation.

      sig_alg: :zeek:type:`count`
         The signature algorithm used for this sct.

      hash_alg: :zeek:type:`count`
         The hash algorithm used for this sct.

      signature: :zeek:type:`string`
         The signature of this SCT.

      source: :zeek:type:`SSL::SctSource`
         Source of this SCT.

      valid: :zeek:type:`bool` :zeek:attr:`&optional`
         Validation result of this SCT.

   This record is used to store information about the SCTs that are
   encountered in a SSL connection.

.. zeek:type:: SSL::SctSource
   :source-code: policy/protocols/ssl/validate-sct.zeek 16 27

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SSL::SCT_X509_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in the extension of
         an X.509 certificate.

      .. zeek:enum:: SSL::SCT_TLS_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in an TLS session
         extension.

      .. zeek:enum:: SSL::SCT_OCSP_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in the extension of
         an stapled OCSP reply.

   List of the different sources for Signed Certificate Timestamp


