:tocdepth: 3

policy/protocols/modbus/track-memmap.bro
========================================
.. bro:namespace:: Modbus

This script tracks the memory map of holding (read/write) registers and logs
changes as they are discovered.

.. todo:: Not all register read and write functions are supported yet.

:Namespace: Modbus
:Imports: :doc:`base/protocols/modbus </scripts/base/protocols/modbus/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================== ==================================================
:bro:id:`Modbus::track_memmap`: :bro:type:`Host` :bro:attr:`&redef` The hosts that should have memory mapping enabled.
=================================================================== ==================================================

State Variables
###############
===================================================== =======================================================
:bro:id:`Modbus::device_registers`: :bro:type:`table` The memory map of slaves is tracked with this variable.
===================================================== =======================================================

Types
#####
===================================================== =====================================================================
:bro:type:`Modbus::MemmapInfo`: :bro:type:`record`    
:bro:type:`Modbus::RegisterValue`: :bro:type:`record` 
:bro:type:`Modbus::Registers`: :bro:type:`table`      Indexed on the device register value and yielding the register value.
===================================================== =====================================================================

Redefinitions
#############
============================================ =
:bro:type:`Log::ID`: :bro:type:`enum`        
:bro:type:`Modbus::Info`: :bro:type:`record` 
============================================ =

Events
######
===================================================== =====================================================================
:bro:id:`Modbus::changed_register`: :bro:type:`event` This event is generated every time a register is seen to be different
                                                      than it was previously seen to be.
===================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Modbus::track_memmap

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   The hosts that should have memory mapping enabled.

State Variables
###############
.. bro:id:: Modbus::device_registers

   :Type: :bro:type:`table` [:bro:type:`addr`] of :bro:type:`Modbus::Registers`
   :Default: ``{}``

   The memory map of slaves is tracked with this variable.

Types
#####
.. bro:type:: Modbus::MemmapInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for the detected register change.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         Connection ID.

      register: :bro:type:`count` :bro:attr:`&log`
         The device memory offset.

      old_val: :bro:type:`count` :bro:attr:`&log`
         The old value stored in the register.

      new_val: :bro:type:`count` :bro:attr:`&log`
         The new value stored in the register.

      delta: :bro:type:`interval` :bro:attr:`&log`
         The time delta between when the *old_val* and *new_val* were
         seen.


.. bro:type:: Modbus::RegisterValue

   :Type: :bro:type:`record`

      last_set: :bro:type:`time`

      value: :bro:type:`count`


.. bro:type:: Modbus::Registers

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`Modbus::RegisterValue`

   Indexed on the device register value and yielding the register value.

Events
######
.. bro:id:: Modbus::changed_register

   :Type: :bro:type:`event` (c: :bro:type:`connection`, register: :bro:type:`count`, old_val: :bro:type:`count`, new_val: :bro:type:`count`, delta: :bro:type:`interval`)

   This event is generated every time a register is seen to be different
   than it was previously seen to be.


