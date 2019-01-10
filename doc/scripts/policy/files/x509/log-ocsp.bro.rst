:tocdepth: 3

policy/files/x509/log-ocsp.bro
==============================
.. bro:namespace:: OCSP

Enable logging of OCSP responses.

:Namespace: OCSP

Summary
~~~~~~~
Types
#####
========================================== ==========================================================
:bro:type:`OCSP::Info`: :bro:type:`record` The record type which contains the fields of the OCSP log.
========================================== ==========================================================

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
=========================================== ===================================================
:bro:id:`OCSP::log_ocsp`: :bro:type:`event` Event that can be handled to access the OCSP record
                                            as it is sent to the logging framework.
=========================================== ===================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: OCSP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the OCSP reply was encountered.

      id: :bro:type:`string` :bro:attr:`&log`
         File id of the OCSP reply.

      hashAlgorithm: :bro:type:`string` :bro:attr:`&log`
         Hash algorithm used to generate issuerNameHash and issuerKeyHash.

      issuerNameHash: :bro:type:`string` :bro:attr:`&log`
         Hash of the issuer's distingueshed name.

      issuerKeyHash: :bro:type:`string` :bro:attr:`&log`
         Hash of the issuer's public key.

      serialNumber: :bro:type:`string` :bro:attr:`&log`
         Serial number of the affected certificate.

      certStatus: :bro:type:`string` :bro:attr:`&log`
         Status of the affected certificate.

      revoketime: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         Time at which the certificate was revoked.

      revokereason: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Reason for which the certificate was revoked.

      thisUpdate: :bro:type:`time` :bro:attr:`&log`
         The time at which the status being shows is known to have been correct.

      nextUpdate: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The latest time at which new information about the status of the certificate will be available.

   The record type which contains the fields of the OCSP log.

Events
######
.. bro:id:: OCSP::log_ocsp

   :Type: :bro:type:`event` (rec: :bro:type:`OCSP::Info`)

   Event that can be handled to access the OCSP record
   as it is sent to the logging framework.


