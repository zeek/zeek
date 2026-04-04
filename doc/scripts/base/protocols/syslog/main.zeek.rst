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
Redefinable Options
###################
============================================================== ============================
:zeek:id:`Syslog::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for Syslog.
============================================================== ============================

Types
#####
============================================== ============================================================
:zeek:type:`Syslog::Info`: :zeek:type:`record` The record type which contains the fields of the syslog log.
============================================== ============================================================

Redefinitions
#############
============================================ ==========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`Syslog::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               syslog: :zeek:type:`Syslog::Info` :zeek:attr:`&optional`
============================================ ==========================================================

Hooks
#####
=========================================================== =
:zeek:id:`Syslog::log_policy`: :zeek:type:`Log::PolicyHook`
=========================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Syslog::ports
   :source-code: base/protocols/syslog/main.zeek 12 12

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            514/udp
         }


   Well-known ports for Syslog.

Types
#####
.. zeek:type:: Syslog::Info
   :source-code: base/protocols/syslog/main.zeek 17 32

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp when the syslog message was seen.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      Protocol over which the message was seen.


   .. zeek:field:: facility :zeek:type:`string` :zeek:attr:`&log`

      Syslog facility for the message.


   .. zeek:field:: severity :zeek:type:`string` :zeek:attr:`&log`

      Syslog severity for the message.


   .. zeek:field:: message :zeek:type:`string` :zeek:attr:`&log`

      The plain text message.


   The record type which contains the fields of the syslog log.

Hooks
#####
.. zeek:id:: Syslog::log_policy
   :source-code: base/protocols/syslog/main.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`



