:tocdepth: 3

base/frameworks/netcontrol/shunt.zeek
=====================================
.. zeek:namespace:: NetControl

Implementation of the shunt functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`

Summary
~~~~~~~
Types
#####
======================================================= =
:zeek:type:`NetControl::ShuntInfo`: :zeek:type:`record` 
======================================================= =

Redefinitions
#############
======================================= =
:zeek:type:`Log::ID`: :zeek:type:`enum` 
======================================= =

Events
######
=============================================================== ==========================================================================
:zeek:id:`NetControl::log_netcontrol_shunt`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
                                                                record as it is sent on to the logging framework.
=============================================================== ==========================================================================

Functions
#########
======================================================== ==========================================================
:zeek:id:`NetControl::shunt_flow`: :zeek:type:`function` Stops forwarding a uni-directional flow's packets to Zeek.
======================================================== ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::ShuntInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time at which the recorded activity occurred.

      rule_id: :zeek:type:`string` :zeek:attr:`&log`
         ID of the rule; unique during each Zeek run.

      f: :zeek:type:`flow_id` :zeek:attr:`&log`
         Flow ID of the shunted flow.

      expire: :zeek:type:`interval` :zeek:attr:`&log`
         Expiry time of the shunt.

      location: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Location where the underlying action was triggered.


Events
######
.. zeek:id:: NetControl::log_netcontrol_shunt

   :Type: :zeek:type:`event` (rec: :zeek:type:`NetControl::ShuntInfo`)

   Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
   record as it is sent on to the logging framework.

Functions
#########
.. zeek:id:: NetControl::shunt_flow

   :Type: :zeek:type:`function` (f: :zeek:type:`flow_id`, t: :zeek:type:`interval`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Stops forwarding a uni-directional flow's packets to Zeek.
   

   :f: The flow to shunt.
   

   :t: How long to leave the shunt in place, with 0 being indefinitely.
   

   :location: An optional string describing where the shunt was triggered.
   

   :returns: The id of the inserted rule on success and zero on failure.


