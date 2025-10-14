:tocdepth: 3

policy/protocols/modbus/known-masters-slaves.zeek
=================================================
.. zeek:namespace:: Known

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
============================================================================================================== ===============================
:zeek:id:`Known::modbus_nodes`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef` The Modbus nodes being tracked.
============================================================================================================== ===============================

Types
#####
======================================================= =
:zeek:type:`Known::ModbusDeviceType`: :zeek:type:`enum` 
:zeek:type:`Known::ModbusInfo`: :zeek:type:`record`     
======================================================= =

Redefinitions
#############
======================================= ================================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`Known::MODBUS_LOG`
======================================= ================================

Events
######
====================================================== =====================================================================
:zeek:id:`Known::log_known_modbus`: :zeek:type:`event` Event that can be handled to access the loggable record as it is sent
                                                       on to the logging framework.
====================================================== =====================================================================

Hooks
#####
================================================================= =
:zeek:id:`Known::log_policy_modbus`: :zeek:type:`Log::PolicyHook` 
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: Known::modbus_nodes
   :source-code: policy/protocols/modbus/known-masters-slaves.zeek 31 31

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`Known::ModbusDeviceType`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`
   :Default: ``{}``

   The Modbus nodes being tracked.

Types
#####
.. zeek:type:: Known::ModbusDeviceType
   :source-code: policy/protocols/modbus/known-masters-slaves.zeek 16 20

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Known::MODBUS_MASTER Known::ModbusDeviceType

      .. zeek:enum:: Known::MODBUS_SLAVE Known::ModbusDeviceType


.. zeek:type:: Known::ModbusInfo
   :source-code: policy/protocols/modbus/known-masters-slaves.zeek 21 28

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time the device was discovered.

      host: :zeek:type:`addr` :zeek:attr:`&log`
         The IP address of the host.

      device_type: :zeek:type:`Known::ModbusDeviceType` :zeek:attr:`&log`
         The type of device being tracked.


Events
######
.. zeek:id:: Known::log_known_modbus
   :source-code: policy/protocols/modbus/known-masters-slaves.zeek 35 35

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::ModbusInfo`)

   Event that can be handled to access the loggable record as it is sent
   on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_modbus
   :source-code: policy/protocols/modbus/known-masters-slaves.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`



