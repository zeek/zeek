:tocdepth: 3

base/files/x509/main.zeek
=========================
.. zeek:namespace:: X509


:Namespace: X509
:Imports: :doc:`base/files/hash </scripts/base/files/hash/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Types
#####
============================================ ===========================================================
:zeek:type:`X509::Info`: :zeek:type:`record` The record type which contains the fields of the X.509 log.
============================================ ===========================================================

Redefinitions
#############
================================================================= =
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
:zeek:type:`Log::ID`: :zeek:type:`enum`                           
================================================================= =

Events
######
============================================= ===================================
:zeek:id:`X509::log_x509`: :zeek:type:`event` Event for accessing logged records.
============================================= ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: X509::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Current timestamp.

      id: :zeek:type:`string` :zeek:attr:`&log`
         File id of this certificate.

      certificate: :zeek:type:`X509::Certificate` :zeek:attr:`&log`
         Basic information about the certificate.

      handle: :zeek:type:`opaque` of x509
         The opaque wrapping the certificate. Mainly used
         for the verify operations.

      extensions: :zeek:type:`vector` of :zeek:type:`X509::Extension` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         All extensions that were encountered in the certificate.

      san: :zeek:type:`X509::SubjectAlternativeName` :zeek:attr:`&optional` :zeek:attr:`&log`
         Subject alternative name extension of the certificate.

      basic_constraints: :zeek:type:`X509::BasicConstraints` :zeek:attr:`&optional` :zeek:attr:`&log`
         Basic constraints extension of the certificate.

      logcert: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-hostcerts-only.zeek` is loaded)

         Logging of certificate is suppressed if set to F

   The record type which contains the fields of the X.509 log.

Events
######
.. zeek:id:: X509::log_x509

   :Type: :zeek:type:`event` (rec: :zeek:type:`X509::Info`)

   Event for accessing logged records.


