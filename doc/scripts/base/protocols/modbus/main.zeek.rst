:tocdepth: 3

base/protocols/modbus/main.zeek
===============================
.. zeek:namespace:: Modbus

Base Modbus analysis script.

:Namespace: Modbus
:Imports: :doc:`base/protocols/modbus/consts.zeek </scripts/base/protocols/modbus/consts.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================== ============================
:zeek:id:`Modbus::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for Modbus.
============================================================== ============================

Types
#####
============================================== =
:zeek:type:`Modbus::Info`: :zeek:type:`record`
============================================== =

Redefinitions
#############
============================================ ==========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`Modbus::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               modbus: :zeek:type:`Modbus::Info` :zeek:attr:`&optional`
============================================ ==========================================================

Events
######
================================================= ===================================================================
:zeek:id:`Modbus::log_modbus`: :zeek:type:`event` Event that can be handled to access the Modbus record as it is sent
                                                  on to the logging framework.
================================================= ===================================================================

Hooks
#####
=========================================================== =
:zeek:id:`Modbus::log_policy`: :zeek:type:`Log::PolicyHook`
=========================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Modbus::ports
   :source-code: base/protocols/modbus/main.zeek 11 11

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            502/tcp
         }


   Well-known ports for Modbus.

Types
#####
.. zeek:type:: Modbus::Info
   :source-code: base/protocols/modbus/main.zeek 15 32

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Time of the request.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique identifier for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      Identifier for the connection.


   .. zeek:field:: tid :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Modbus transaction ID


   .. zeek:field:: unit :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The terminal unit identifier for the message


   .. zeek:field:: func :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The name of the function message that was sent.


   .. zeek:field:: pdu_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Whether this PDU was a response ("RESP") or request ("REQ")


   .. zeek:field:: exception :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The exception if the response was a failure.


   .. zeek:field:: track_address :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/modbus/track-memmap.zeek` is loaded)



Events
######
.. zeek:id:: Modbus::log_modbus
   :source-code: base/protocols/modbus/main.zeek 36 36

   :Type: :zeek:type:`event` (rec: :zeek:type:`Modbus::Info`)

   Event that can be handled to access the Modbus record as it is sent
   on to the logging framework.

Hooks
#####
.. zeek:id:: Modbus::log_policy
   :source-code: base/protocols/modbus/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



