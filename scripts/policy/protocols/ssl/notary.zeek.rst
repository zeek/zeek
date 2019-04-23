:tocdepth: 3

policy/protocols/ssl/notary.zeek
================================
.. zeek:namespace:: CertNotary


:Namespace: CertNotary
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== ===========================
:zeek:id:`CertNotary::domain`: :zeek:type:`string` :zeek:attr:`&redef` The notary domain to query.
====================================================================== ===========================

Types
#####
====================================================== ============================================
:zeek:type:`CertNotary::Response`: :zeek:type:`record` A response from the ICSI certificate notary.
====================================================== ============================================

Redefinitions
#############
=========================================== =
:zeek:type:`SSL::Info`: :zeek:type:`record` 
=========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: CertNotary::domain

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"notary.icsi.berkeley.edu"``

   The notary domain to query.

Types
#####
.. zeek:type:: CertNotary::Response

   :Type: :zeek:type:`record`

      first_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      last_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      times_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      valid: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

   A response from the ICSI certificate notary.


