:tocdepth: 3

base/protocols/modbus/main.zeek
===============================
.. zeek:namespace:: Modbus

Base Modbus analysis script.

:Namespace: Modbus
:Imports: :doc:`base/protocols/modbus/consts.zeek </scripts/base/protocols/modbus/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================== =
:zeek:type:`Modbus::Info`: :zeek:type:`record` 
============================================== =

Redefinitions
#############
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
================================================= ===================================================================
:zeek:id:`Modbus::log_modbus`: :zeek:type:`event` Event that can be handled to access the Modbus record as it is sent
                                                  on to the logging framework.
================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Modbus::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time of the request.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique identifier for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         Identifier for the connection.

      func: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The name of the function message that was sent.

      exception: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The exception if the response was a failure.

      track_address: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/modbus/track-memmap.zeek` is loaded)



Events
######
.. zeek:id:: Modbus::log_modbus

   :Type: :zeek:type:`event` (rec: :zeek:type:`Modbus::Info`)

   Event that can be handled to access the Modbus record as it is sent
   on to the logging framework.


