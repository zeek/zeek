:tocdepth: 3

policy/protocols/ssl/validate-certs.zeek
========================================
.. bro:namespace:: SSL

Perform full certificate chain validation for SSL certificates.

:Namespace: SSL
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
State Variables
###############
===================================================================================================================== ==================================================================
:bro:id:`SSL::recently_validated_certs`: :bro:type:`table` :bro:attr:`&read_expire` = ``5.0 mins`` :bro:attr:`&redef` Result values for recently validated chains along with the
                                                                                                                      validation status are kept in this table to avoid constant
                                                                                                                      validation every time the same certificate chain is seen.
:bro:id:`SSL::ssl_cache_intermediate_ca`: :bro:type:`bool` :bro:attr:`&redef`                                         Use intermediate CA certificate caching when trying to validate
                                                                                                                      certificates.
:bro:id:`SSL::ssl_store_valid_chain`: :bro:type:`bool` :bro:attr:`&redef`                                             Store the valid chain in c$ssl$valid_chain if validation succeeds.
===================================================================================================================== ==================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
:bro:type:`SSL::Info`: :bro:type:`record`  
========================================== =

Events
######
================================================== ===============================================================
:bro:id:`SSL::intermediate_add`: :bro:type:`event` Event from a manager to workers when encountering a new, valid
                                                   intermediate.
:bro:id:`SSL::new_intermediate`: :bro:type:`event` Event from workers to the manager when a new intermediate chain
                                                   is to be added.
================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. bro:id:: SSL::recently_validated_certs

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`X509::Result`
   :Attributes: :bro:attr:`&read_expire` = ``5.0 mins`` :bro:attr:`&redef`
   :Default: ``{}``

   Result values for recently validated chains along with the
   validation status are kept in this table to avoid constant
   validation every time the same certificate chain is seen.

.. bro:id:: SSL::ssl_cache_intermediate_ca

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Use intermediate CA certificate caching when trying to validate
   certificates. When this is enabled, Bro keeps track of all valid
   intermediate CA certificates that it has seen in the past. When
   encountering a host certificate that cannot be validated because
   of missing intermediate CA certificate, the cached list is used
   to try to validate the cert. This is similar to how Firefox is
   doing certificate validation.
   
   Disabling this will usually greatly increase the number of validation warnings
   that you encounter. Only disable if you want to find misconfigured servers.

.. bro:id:: SSL::ssl_store_valid_chain

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Store the valid chain in c$ssl$valid_chain if validation succeeds.
   This has a potentially high memory impact, depending on the local environment
   and is thus disabled by default.

Events
######
.. bro:id:: SSL::intermediate_add

   :Type: :bro:type:`event` (key: :bro:type:`string`, value: :bro:type:`vector` of :bro:type:`opaque` of x509)

   Event from a manager to workers when encountering a new, valid
   intermediate.

.. bro:id:: SSL::new_intermediate

   :Type: :bro:type:`event` (key: :bro:type:`string`, value: :bro:type:`vector` of :bro:type:`opaque` of x509)

   Event from workers to the manager when a new intermediate chain
   is to be added.


