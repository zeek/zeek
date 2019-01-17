:tocdepth: 3

policy/protocols/modbus/known-masters-slaves.bro
================================================
.. bro:namespace:: Known

Script for tracking known Modbus masters and slaves.

.. todo:: This script needs a lot of work.  What might be more interesting
         is to track master/slave relationships based on commands sent and
         successful (non-exception) responses.

:Namespace: Known
:Imports: :doc:`base/protocols/modbus </scripts/base/protocols/modbus/index>`

Summary
~~~~~~~
State Variables
###############
========================================================================================================== ===============================
:bro:id:`Known::modbus_nodes`: :bro:type:`set` :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef` The Modbus nodes being tracked.
========================================================================================================== ===============================

Types
#####
===================================================== =
:bro:type:`Known::ModbusDeviceType`: :bro:type:`enum` 
:bro:type:`Known::ModbusInfo`: :bro:type:`record`     
===================================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
==================================================== =====================================================================
:bro:id:`Known::log_known_modbus`: :bro:type:`event` Event that can be handled to access the loggable record as it is sent
                                                     on to the logging framework.
==================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. bro:id:: Known::modbus_nodes

   :Type: :bro:type:`set` [:bro:type:`addr`, :bro:type:`Known::ModbusDeviceType`]
   :Attributes: :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef`
   :Default: ``{}``

   The Modbus nodes being tracked.

Types
#####
.. bro:type:: Known::ModbusDeviceType

   :Type: :bro:type:`enum`

      .. bro:enum:: Known::MODBUS_MASTER Known::ModbusDeviceType

      .. bro:enum:: Known::MODBUS_SLAVE Known::ModbusDeviceType


.. bro:type:: Known::ModbusInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The time the device was discovered.

      host: :bro:type:`addr` :bro:attr:`&log`
         The IP address of the host.

      device_type: :bro:type:`Known::ModbusDeviceType` :bro:attr:`&log`
         The type of device being tracked.


Events
######
.. bro:id:: Known::log_known_modbus

   :Type: :bro:type:`event` (rec: :bro:type:`Known::ModbusInfo`)

   Event that can be handled to access the loggable record as it is sent
   on to the logging framework.


