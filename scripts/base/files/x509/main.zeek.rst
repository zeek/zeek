:tocdepth: 3

base/files/x509/main.zeek
=========================
.. bro:namespace:: X509


:Namespace: X509
:Imports: :doc:`base/files/hash </scripts/base/files/hash/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Types
#####
========================================== ===========================================================
:bro:type:`X509::Info`: :bro:type:`record` The record type which contains the fields of the X.509 log.
========================================== ===========================================================

Redefinitions
#############
============================================================== =
:bro:type:`Files::Info`: :bro:type:`record` :bro:attr:`&redef` 
:bro:type:`Log::ID`: :bro:type:`enum`                          
============================================================== =

Events
######
=========================================== ===================================
:bro:id:`X509::log_x509`: :bro:type:`event` Event for accessing logged records.
=========================================== ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: X509::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Current timestamp.

      id: :bro:type:`string` :bro:attr:`&log`
         File id of this certificate.

      certificate: :bro:type:`X509::Certificate` :bro:attr:`&log`
         Basic information about the certificate.

      handle: :bro:type:`opaque` of x509
         The opaque wrapping the certificate. Mainly used
         for the verify operations.

      extensions: :bro:type:`vector` of :bro:type:`X509::Extension` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         All extensions that were encountered in the certificate.

      san: :bro:type:`X509::SubjectAlternativeName` :bro:attr:`&optional` :bro:attr:`&log`
         Subject alternative name extension of the certificate.

      basic_constraints: :bro:type:`X509::BasicConstraints` :bro:attr:`&optional` :bro:attr:`&log`
         Basic constraints extension of the certificate.

      logcert: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-hostcerts-only.zeek` is loaded)

         Logging of certificate is suppressed if set to F

   The record type which contains the fields of the X.509 log.

Events
######
.. bro:id:: X509::log_x509

   :Type: :bro:type:`event` (rec: :bro:type:`X509::Info`)

   Event for accessing logged records.


