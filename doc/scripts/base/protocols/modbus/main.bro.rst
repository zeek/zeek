:tocdepth: 3

base/protocols/modbus/main.bro
==============================
.. bro:namespace:: Modbus

Base Modbus analysis script.

:Namespace: Modbus
:Imports: :doc:`base/protocols/modbus/consts.bro </scripts/base/protocols/modbus/consts.bro>`

Summary
~~~~~~~
Types
#####
============================================ =
:bro:type:`Modbus::Info`: :bro:type:`record` 
============================================ =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=============================================== ===================================================================
:bro:id:`Modbus::log_modbus`: :bro:type:`event` Event that can be handled to access the Modbus record as it is sent
                                                on to the logging framework.
=============================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Modbus::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time of the request.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique identifier for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         Identifier for the connection.

      func: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The name of the function message that was sent.

      exception: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The exception if the response was a failure.

      track_address: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/modbus/track-memmap.bro` is loaded)



Events
######
.. bro:id:: Modbus::log_modbus

   :Type: :bro:type:`event` (rec: :bro:type:`Modbus::Info`)

   Event that can be handled to access the Modbus record as it is sent
   on to the logging framework.


