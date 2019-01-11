:tocdepth: 3

policy/protocols/ssl/notary.bro
===============================
.. bro:namespace:: CertNotary


:Namespace: CertNotary
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================== ===========================
:bro:id:`CertNotary::domain`: :bro:type:`string` :bro:attr:`&redef` The notary domain to query.
=================================================================== ===========================

Types
#####
==================================================== ============================================
:bro:type:`CertNotary::Response`: :bro:type:`record` A response from the ICSI certificate notary.
==================================================== ============================================

Redefinitions
#############
========================================= =
:bro:type:`SSL::Info`: :bro:type:`record` 
========================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: CertNotary::domain

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"notary.icsi.berkeley.edu"``

   The notary domain to query.

Types
#####
.. bro:type:: CertNotary::Response

   :Type: :bro:type:`record`

      first_seen: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`

      last_seen: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`

      times_seen: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`

      valid: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`

   A response from the ICSI certificate notary.


