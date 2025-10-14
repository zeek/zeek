:tocdepth: 3

base/protocols/syslog/main.zeek
===============================
.. zeek:namespace:: Syslog

Core script support for logging syslog messages.  This script represents
one syslog message as one logged record.

:Namespace: Syslog
:Imports: :doc:`base/protocols/syslog/consts.zeek </scripts/base/protocols/syslog/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================== ============================================================
:zeek:type:`Syslog::Info`: :zeek:type:`record` The record type which contains the fields of the syslog log.
============================================== ============================================================

Redefinitions
#############
==================================================================== ==========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`Syslog::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       syslog: :zeek:type:`Syslog::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ==========================================================

Hooks
#####
=========================================================== =
:zeek:id:`Syslog::log_policy`: :zeek:type:`Log::PolicyHook` 
=========================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Syslog::Info
   :source-code: base/protocols/syslog/main.zeek 14 29

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp when the syslog message was seen.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      proto: :zeek:type:`transport_proto` :zeek:attr:`&log`
         Protocol over which the message was seen.

      facility: :zeek:type:`string` :zeek:attr:`&log`
         Syslog facility for the message.

      severity: :zeek:type:`string` :zeek:attr:`&log`
         Syslog severity for the message.

      message: :zeek:type:`string` :zeek:attr:`&log`
         The plain text message.

   The record type which contains the fields of the syslog log.

Hooks
#####
.. zeek:id:: Syslog::log_policy
   :source-code: base/protocols/syslog/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



