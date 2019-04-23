:tocdepth: 3

base/frameworks/netcontrol/drop.zeek
====================================
.. zeek:namespace:: NetControl

Implementation of the drop functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`

Summary
~~~~~~~
Types
#####
====================================================== =
:zeek:type:`NetControl::DropInfo`: :zeek:type:`record` 
====================================================== =

Redefinitions
#############
======================================= =
:zeek:type:`Log::ID`: :zeek:type:`enum` 
======================================= =

Events
######
============================================================== ==========================================================================
:zeek:id:`NetControl::log_netcontrol_drop`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
                                                               record as it is sent on to the logging framework.
============================================================== ==========================================================================

Hooks
#####
========================================================== =======================================================================
:zeek:id:`NetControl::drop_rule_policy`: :zeek:type:`hook` Hook that allows the modification of rules passed to drop_* before they
                                                           are passed on.
========================================================== =======================================================================

Functions
#########
============================================================= ======================================================================
:zeek:id:`NetControl::drop_address`: :zeek:type:`function`    Stops all packets involving an IP address from being forwarded.
:zeek:id:`NetControl::drop_connection`: :zeek:type:`function` Stops all packets involving a connection address from being forwarded.
============================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::DropInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :zeek:type:`string` :zeek:attr:`&log`
         ID of the rule; unique during each Bro run.

      orig_h: :zeek:type:`addr` :zeek:attr:`&log`
         The originator's IP address.

      orig_p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         The originator's port number.

      resp_h: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         The responder's IP address.

      resp_p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         The responder's port number.

      expire: :zeek:type:`interval` :zeek:attr:`&log`
         Expiry time of the shunt.

      location: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Location where the underlying action was triggered.


Events
######
.. zeek:id:: NetControl::log_netcontrol_drop

   :Type: :zeek:type:`event` (rec: :zeek:type:`NetControl::DropInfo`)

   Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: NetControl::drop_rule_policy

   :Type: :zeek:type:`hook` (r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool`

   Hook that allows the modification of rules passed to drop_* before they
   are passed on. If one of the hooks uses break, the rule is ignored.
   

   :r: The rule to be added.

Functions
#########
.. zeek:id:: NetControl::drop_address

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Stops all packets involving an IP address from being forwarded.
   

   :a: The address to be dropped.
   

   :t: How long to drop it, with 0 being indefinitely.
   

   :location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.

.. zeek:id:: NetControl::drop_connection

   :Type: :zeek:type:`function` (c: :zeek:type:`conn_id`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Stops all packets involving a connection address from being forwarded.
   

   :c: The connection to be dropped.
   

   :t: How long to drop it, with 0 being indefinitely.
   

   :location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.


