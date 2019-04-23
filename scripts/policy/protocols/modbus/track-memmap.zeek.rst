:tocdepth: 3

policy/protocols/modbus/track-memmap.zeek
=========================================
.. zeek:namespace:: Modbus

This script tracks the memory map of holding (read/write) registers and logs
changes as they are discovered.

.. todo:: Not all register read and write functions are supported yet.

:Namespace: Modbus
:Imports: :doc:`base/protocols/modbus </scripts/base/protocols/modbus/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== ==================================================
:zeek:id:`Modbus::track_memmap`: :zeek:type:`Host` :zeek:attr:`&redef` The hosts that should have memory mapping enabled.
====================================================================== ==================================================

State Variables
###############
======================================================= =======================================================
:zeek:id:`Modbus::device_registers`: :zeek:type:`table` The memory map of slaves is tracked with this variable.
======================================================= =======================================================

Types
#####
======================================================= =====================================================================
:zeek:type:`Modbus::MemmapInfo`: :zeek:type:`record`    
:zeek:type:`Modbus::RegisterValue`: :zeek:type:`record` 
:zeek:type:`Modbus::Registers`: :zeek:type:`table`      Indexed on the device register value and yielding the register value.
======================================================= =====================================================================

Redefinitions
#############
============================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`        
:zeek:type:`Modbus::Info`: :zeek:type:`record` 
============================================== =

Events
######
======================================================= =====================================================================
:zeek:id:`Modbus::changed_register`: :zeek:type:`event` This event is generated every time a register is seen to be different
                                                        than it was previously seen to be.
======================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Modbus::track_memmap

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``ALL_HOSTS``

   The hosts that should have memory mapping enabled.

State Variables
###############
.. zeek:id:: Modbus::device_registers

   :Type: :zeek:type:`table` [:zeek:type:`addr`] of :zeek:type:`Modbus::Registers`
   :Default: ``{}``

   The memory map of slaves is tracked with this variable.

Types
#####
.. zeek:type:: Modbus::MemmapInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for the detected register change.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         Connection ID.

      register: :zeek:type:`count` :zeek:attr:`&log`
         The device memory offset.

      old_val: :zeek:type:`count` :zeek:attr:`&log`
         The old value stored in the register.

      new_val: :zeek:type:`count` :zeek:attr:`&log`
         The new value stored in the register.

      delta: :zeek:type:`interval` :zeek:attr:`&log`
         The time delta between when the *old_val* and *new_val* were
         seen.


.. zeek:type:: Modbus::RegisterValue

   :Type: :zeek:type:`record`

      last_set: :zeek:type:`time`

      value: :zeek:type:`count`


.. zeek:type:: Modbus::Registers

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`Modbus::RegisterValue`

   Indexed on the device register value and yielding the register value.

Events
######
.. zeek:id:: Modbus::changed_register

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, register: :zeek:type:`count`, old_val: :zeek:type:`count`, new_val: :zeek:type:`count`, delta: :zeek:type:`interval`)

   This event is generated every time a register is seen to be different
   than it was previously seen to be.


