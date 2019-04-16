:tocdepth: 3

base/frameworks/netcontrol/shunt.zeek
=====================================
.. bro:namespace:: NetControl

Implementation of the shunt functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`

Summary
~~~~~~~
Types
#####
===================================================== =
:bro:type:`NetControl::ShuntInfo`: :bro:type:`record` 
===================================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
============================================================= =========================================================================
:bro:id:`NetControl::log_netcontrol_shunt`: :bro:type:`event` Event that can be handled to access the :bro:type:`NetControl::ShuntInfo`
                                                              record as it is sent on to the logging framework.
============================================================= =========================================================================

Functions
#########
====================================================== =========================================================
:bro:id:`NetControl::shunt_flow`: :bro:type:`function` Stops forwarding a uni-directional flow's packets to Bro.
====================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::ShuntInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :bro:type:`string` :bro:attr:`&log`
         ID of the rule; unique during each Bro run.

      f: :bro:type:`flow_id` :bro:attr:`&log`
         Flow ID of the shunted flow.

      expire: :bro:type:`interval` :bro:attr:`&log`
         Expiry time of the shunt.

      location: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Location where the underlying action was triggered.


Events
######
.. bro:id:: NetControl::log_netcontrol_shunt

   :Type: :bro:type:`event` (rec: :bro:type:`NetControl::ShuntInfo`)

   Event that can be handled to access the :bro:type:`NetControl::ShuntInfo`
   record as it is sent on to the logging framework.

Functions
#########
.. bro:id:: NetControl::shunt_flow

   :Type: :bro:type:`function` (f: :bro:type:`flow_id`, t: :bro:type:`interval`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`string`

   Stops forwarding a uni-directional flow's packets to Bro.
   

   :f: The flow to shunt.
   

   :t: How long to leave the shunt in place, with 0 being indefinitely.
   

   :location: An optional string describing where the shunt was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.


