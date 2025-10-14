:tocdepth: 3

base/files/x509/log-ocsp.zeek
=============================
.. zeek:namespace:: OCSP

Enable logging of OCSP responses.

:Namespace: OCSP

Summary
~~~~~~~
Types
#####
============================================ ==========================================================
:zeek:type:`OCSP::Info`: :zeek:type:`record` The record type which contains the fields of the OCSP log.
============================================ ==========================================================

Redefinitions
#############
======================================= ========================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`OCSP::LOG`
======================================= ========================

Events
######
============================================= ===================================================
:zeek:id:`OCSP::log_ocsp`: :zeek:type:`event` Event that can be handled to access the OCSP record
                                              as it is sent to the logging framework.
============================================= ===================================================

Hooks
#####
========================================================= =
:zeek:id:`OCSP::log_policy`: :zeek:type:`Log::PolicyHook` 
========================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: OCSP::Info
   :source-code: base/files/x509/log-ocsp.zeek 11 34

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the OCSP reply was encountered.

      id: :zeek:type:`string` :zeek:attr:`&log`
         File id of the OCSP reply.

      hashAlgorithm: :zeek:type:`string` :zeek:attr:`&log`
         Hash algorithm used to generate issuerNameHash and issuerKeyHash.

      issuerNameHash: :zeek:type:`string` :zeek:attr:`&log`
         Hash of the issuer's distinguished name.

      issuerKeyHash: :zeek:type:`string` :zeek:attr:`&log`
         Hash of the issuer's public key.

      serialNumber: :zeek:type:`string` :zeek:attr:`&log`
         Serial number of the affected certificate.

      certStatus: :zeek:type:`string` :zeek:attr:`&log`
         Status of the affected certificate.

      revoketime: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         Time at which the certificate was revoked.

      revokereason: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Reason for which the certificate was revoked.

      thisUpdate: :zeek:type:`time` :zeek:attr:`&log`
         The time at which the status being shows is known to have been correct.

      nextUpdate: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         The latest time at which new information about the status of the certificate will be available.

   The record type which contains the fields of the OCSP log.

Events
######
.. zeek:id:: OCSP::log_ocsp
   :source-code: base/files/x509/log-ocsp.zeek 38 38

   :Type: :zeek:type:`event` (rec: :zeek:type:`OCSP::Info`)

   Event that can be handled to access the OCSP record
   as it is sent to the logging framework.

Hooks
#####
.. zeek:id:: OCSP::log_policy
   :source-code: base/files/x509/log-ocsp.zeek 8 8

   :Type: :zeek:type:`Log::PolicyHook`



