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
======================================= ===================================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`NetControl::DROP_LOG`
======================================= ===================================

Events
######
============================================================== ==========================================================================
:zeek:id:`NetControl::log_netcontrol_drop`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
                                                               record as it is sent on to the logging framework.
============================================================== ==========================================================================

Hooks
#####
==================================================================== =======================================================================
:zeek:id:`NetControl::drop_rule_policy`: :zeek:type:`hook`           Hook that allows the modification of rules passed to drop_* before they
                                                                     are passed on.
:zeek:id:`NetControl::log_policy_drop`: :zeek:type:`Log::PolicyHook` 
==================================================================== =======================================================================

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
   :source-code: base/frameworks/netcontrol/drop.zeek 34 47

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :zeek:type:`string` :zeek:attr:`&log`
         ID of the rule; unique during each Zeek run.

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
   :source-code: base/frameworks/netcontrol/drop.zeek 57 57

   :Type: :zeek:type:`event` (rec: :zeek:type:`NetControl::DropInfo`)

   Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: NetControl::drop_rule_policy
   :source-code: base/frameworks/netcontrol/drop.zeek 53 53

   :Type: :zeek:type:`hook` (r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool`

   Hook that allows the modification of rules passed to drop_* before they
   are passed on. If one of the hooks uses break, the rule is ignored.
   

   :param r: The rule to be added.

.. zeek:id:: NetControl::log_policy_drop
   :source-code: base/frameworks/netcontrol/drop.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: NetControl::drop_address
   :source-code: base/frameworks/netcontrol/drop.zeek 89 111

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Stops all packets involving an IP address from being forwarded.
   

   :param a: The address to be dropped.
   

   :param t: How long to drop it, with 0 being indefinitely.
   

   :param location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.

.. zeek:id:: NetControl::drop_connection
   :source-code: base/frameworks/netcontrol/drop.zeek 65 87

   :Type: :zeek:type:`function` (c: :zeek:type:`conn_id`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Stops all packets involving a connection address from being forwarded.
   

   :param c: The connection to be dropped.
   

   :param t: How long to drop it, with 0 being indefinitely.
   

   :param location: An optional string describing where the drop was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.


