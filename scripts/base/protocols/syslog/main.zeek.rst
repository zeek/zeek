:tocdepth: 3

base/protocols/syslog/main.zeek
===============================
.. bro:namespace:: Syslog

Core script support for logging syslog messages.  This script represents 
one syslog message as one logged record.

:Namespace: Syslog
:Imports: :doc:`base/protocols/syslog/consts.zeek </scripts/base/protocols/syslog/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================ ============================================================
:bro:type:`Syslog::Info`: :bro:type:`record` The record type which contains the fields of the syslog log.
============================================ ============================================================

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Syslog::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp when the syslog message was seen.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      proto: :bro:type:`transport_proto` :bro:attr:`&log`
         Protocol over which the message was seen.

      facility: :bro:type:`string` :bro:attr:`&log`
         Syslog facility for the message.

      severity: :bro:type:`string` :bro:attr:`&log`
         Syslog severity for the message.

      message: :bro:type:`string` :bro:attr:`&log`
         The plain text message.

   The record type which contains the fields of the syslog log.


