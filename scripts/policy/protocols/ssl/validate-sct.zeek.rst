:tocdepth: 3

policy/protocols/ssl/validate-sct.zeek
======================================
.. bro:namespace:: SSL

Perform validation of Signed Certificate Timestamps, as used
for Certificate Transparency. See RFC6962 for more details.

:Namespace: SSL
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`policy/protocols/ssl/validate-certs.zeek </scripts/policy/protocols/ssl/validate-certs.zeek>`

Summary
~~~~~~~
Types
#####
============================================ ================================================================
:bro:type:`SSL::SctInfo`: :bro:type:`record` This record is used to store information about the SCTs that are
                                             encountered in a SSL connection.
:bro:type:`SSL::SctSource`: :bro:type:`enum` List of the different sources for Signed Certificate Timestamp
============================================ ================================================================

Redefinitions
#############
========================================================================= =
:bro:type:`SSL::Info`: :bro:type:`record`                                 
:bro:id:`SSL::ssl_store_valid_chain`: :bro:type:`bool` :bro:attr:`&redef` 
========================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: SSL::SctInfo

   :Type: :bro:type:`record`

      version: :bro:type:`count`
         The version of the encountered SCT (should always be 0 for v1).

      logid: :bro:type:`string`
         The ID of the log issuing this SCT.

      timestamp: :bro:type:`count`
         The timestamp at which this SCT was issued measured since the
         epoch (January 1, 1970, 00:00), ignoring leap seconds, in
         milliseconds. Not converted to a Bro timestamp because we need
         the exact value for validation.

      sig_alg: :bro:type:`count`
         The signature algorithm used for this sct.

      hash_alg: :bro:type:`count`
         The hash algorithm used for this sct.

      signature: :bro:type:`string`
         The signature of this SCT.

      source: :bro:type:`SSL::SctSource`
         Source of this SCT.

      valid: :bro:type:`bool` :bro:attr:`&optional`
         Validation result of this SCT.

   This record is used to store information about the SCTs that are
   encountered in a SSL connection.

.. bro:type:: SSL::SctSource

   :Type: :bro:type:`enum`

      .. bro:enum:: SSL::SCT_X509_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in the extension of
         an X.509 certificate.

      .. bro:enum:: SSL::SCT_TLS_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in an TLS session
         extension.

      .. bro:enum:: SSL::SCT_OCSP_EXT SSL::SctSource

         Signed Certificate Timestamp was encountered in the extension of
         an stapled OCSP reply.

   List of the different sources for Signed Certificate Timestamp


