:tocdepth: 3

policy/protocols/ssl/validate-certs.zeek
========================================
.. zeek:namespace:: SSL

Perform full certificate chain validation for SSL certificates.

:Namespace: SSL
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
State Variables
###############
========================================================================================================================= ==================================================================
:zeek:id:`SSL::recently_validated_certs`: :zeek:type:`table` :zeek:attr:`&read_expire` = ``5.0 mins`` :zeek:attr:`&redef` Result values for recently validated chains along with the
                                                                                                                          validation status are kept in this table to avoid constant
                                                                                                                          validation every time the same certificate chain is seen.
:zeek:id:`SSL::ssl_cache_intermediate_ca`: :zeek:type:`bool` :zeek:attr:`&redef`                                          Use intermediate CA certificate caching when trying to validate
                                                                                                                          certificates.
:zeek:id:`SSL::ssl_store_valid_chain`: :zeek:type:`bool` :zeek:attr:`&redef`                                              Store the valid chain in c$ssl$valid_chain if validation succeeds.
========================================================================================================================= ==================================================================

Redefinitions
#############
============================================ ========================================================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSL::Invalid_Server_Cert`:
                                               This notice indicates that the result of validating the
                                               certificate along with its full certificate chain was
                                               invalid.
:zeek:type:`SSL::Info`: :zeek:type:`record`  
                                             
                                             :New Fields: :zeek:type:`SSL::Info`
                                             
                                               validation_status: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Result of certificate validation for this connection.
                                             
                                               validation_code: :zeek:type:`int` :zeek:attr:`&optional`
                                                 Result of certificate validation for this connection, given
                                                 as OpenSSL validation code.
                                             
                                               valid_chain: :zeek:type:`vector` of :zeek:type:`opaque` of x509 :zeek:attr:`&optional`
                                                 Ordered chain of validated certificate, if validation succeeded.
============================================ ========================================================================================

Events
######
==================================================== ===============================================================
:zeek:id:`SSL::intermediate_add`: :zeek:type:`event` Event from a manager to workers when encountering a new, valid
                                                     intermediate.
:zeek:id:`SSL::new_intermediate`: :zeek:type:`event` Event from workers to the manager when a new intermediate chain
                                                     is to be added.
==================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: SSL::recently_validated_certs
   :source-code: policy/protocols/ssl/validate-certs.zeek 33 33

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`X509::Result`
   :Attributes: :zeek:attr:`&read_expire` = ``5.0 mins`` :zeek:attr:`&redef`
   :Default: ``{}``

   Result values for recently validated chains along with the
   validation status are kept in this table to avoid constant
   validation every time the same certificate chain is seen.

.. zeek:id:: SSL::ssl_cache_intermediate_ca
   :source-code: policy/protocols/ssl/validate-certs.zeek 46 46

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Use intermediate CA certificate caching when trying to validate
   certificates. When this is enabled, Zeek keeps track of all valid
   intermediate CA certificates that it has seen in the past. When
   encountering a host certificate that cannot be validated because
   of missing intermediate CA certificate, the cached list is used
   to try to validate the cert. This is similar to how Firefox is
   doing certificate validation.
   
   Disabling this will usually greatly increase the number of validation warnings
   that you encounter. Only disable if you want to find misconfigured servers.

.. zeek:id:: SSL::ssl_store_valid_chain
   :source-code: policy/protocols/ssl/validate-certs.zeek 51 51

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``
   :Redefinition: from :doc:`/scripts/policy/protocols/ssl/validate-sct.zeek`

      ``=``::

         T


   Store the valid chain in c$ssl$valid_chain if validation succeeds.
   This has a potentially high memory impact, depending on the local environment
   and is thus disabled by default.

Events
######
.. zeek:id:: SSL::intermediate_add
   :source-code: policy/protocols/ssl/validate-certs.zeek 55 55

   :Type: :zeek:type:`event` (key: :zeek:type:`string`, value: :zeek:type:`vector` of :zeek:type:`opaque` of x509)

   Event from a manager to workers when encountering a new, valid
   intermediate.

.. zeek:id:: SSL::new_intermediate
   :source-code: policy/protocols/ssl/validate-certs.zeek 59 59

   :Type: :zeek:type:`event` (key: :zeek:type:`string`, value: :zeek:type:`vector` of :zeek:type:`opaque` of x509)

   Event from workers to the manager when a new intermediate chain
   is to be added.


