:tocdepth: 3

base/frameworks/netcontrol/drop.bro
===================================
.. bro:namespace:: NetControl

Implementation of the drop functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.bro </scripts/base/frameworks/netcontrol/main.bro>`

Summary
~~~~~~~
Types
#####
==================================================== =
:bro:type:`NetControl::DropInfo`: :bro:type:`record` 
==================================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
============================================================ =========================================================================
:bro:id:`NetControl::log_netcontrol_drop`: :bro:type:`event` Event that can be handled to access the :bro:type:`NetControl::ShuntInfo`
                                                             record as it is sent on to the logging framework.
============================================================ =========================================================================

Hooks
#####
======================================================== =======================================================================
:bro:id:`NetControl::drop_rule_policy`: :bro:type:`hook` Hook that allows the modification of rules passed to drop_* before they
                                                         are passed on.
======================================================== =======================================================================

Functions
#########
=========================================================== ======================================================================
:bro:id:`NetControl::drop_address`: :bro:type:`function`    Stops all packets involving an IP address from being forwarded.
:bro:id:`NetControl::drop_connection`: :bro:type:`function` Stops all packets involving a connection address from being forwarded.
=========================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::DropInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :bro:type:`string` :bro:attr:`&log`
         ID of the rule; unique during each Bro run.

      orig_h: :bro:type:`addr` :bro:attr:`&log`
         The originator's IP address.

      orig_p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         The originator's port number.

      resp_h: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         The responder's IP address.

      resp_p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         The responder's port number.

      expire: :bro:type:`interval` :bro:attr:`&log`
         Expiry time of the shunt.

      location: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Location where the underlying action was triggered.


Events
######
.. bro:id:: NetControl::log_netcontrol_drop

   :Type: :bro:type:`event` (rec: :bro:type:`NetControl::DropInfo`)

   Event that can be handled to access the :bro:type:`NetControl::ShuntInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. bro:id:: NetControl::drop_rule_policy

   :Type: :bro:type:`hook` (r: :bro:type:`NetControl::Rule`) : :bro:type:`bool`

   Hook that allows the modification of rules passed to drop_* before they
   are passed on. If one of the hooks uses break, the rule is ignored.
   

   :r: The rule to be added.

Functions
#########
.. bro:id:: NetControl::drop_address

   :Type: :bro:type:`function` (a: :bro:type:`addr`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Stops all packets involving an IP address from being forwarded.
   

   :a: The address to be dropped.
   

   :t: How long to drop it, with 0 being indefinitely.
   

   :location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.

.. bro:id:: NetControl::drop_connection

   :Type: :bro:type:`function` (c: :bro:type:`conn_id`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Stops all packets involving a connection address from being forwarded.
   

   :c: The connection to be dropped.
   

   :t: How long to drop it, with 0 being indefinitely.
   

   :location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.


