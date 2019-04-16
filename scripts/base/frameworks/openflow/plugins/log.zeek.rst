:tocdepth: 3

base/frameworks/openflow/plugins/log.zeek
=========================================
.. bro:namespace:: OpenFlow

OpenFlow plugin that outputs flow-modification commands
to a Bro log file.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Types
#####
============================================== =================================================================
:bro:type:`OpenFlow::Info`: :bro:type:`record` The record type which contains column fields of the OpenFlow log.
============================================== =================================================================

Redefinitions
#############
============================================================================ =
:bro:type:`Log::ID`: :bro:type:`enum`                                        
:bro:type:`OpenFlow::ControllerState`: :bro:type:`record` :bro:attr:`&redef` 
:bro:type:`OpenFlow::Plugin`: :bro:type:`enum`                               
============================================================================ =

Events
######
=================================================== ==================================================================
:bro:id:`OpenFlow::log_openflow`: :bro:type:`event` Event that can be handled to access the :bro:type:`OpenFlow::Info`
                                                    record as it is sent on to the logging framework.
=================================================== ==================================================================

Functions
#########
================================================= ===========================
:bro:id:`OpenFlow::log_new`: :bro:type:`function` Log controller constructor.
================================================= ===========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: OpenFlow::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Network time.

      dpid: :bro:type:`count` :bro:attr:`&log`
         OpenFlow switch datapath id.

      match: :bro:type:`OpenFlow::ofp_match` :bro:attr:`&log`
         OpenFlow match fields.

      flow_mod: :bro:type:`OpenFlow::ofp_flow_mod` :bro:attr:`&log`
         OpenFlow modify flow entry message.

   The record type which contains column fields of the OpenFlow log.

Events
######
.. bro:id:: OpenFlow::log_openflow

   :Type: :bro:type:`event` (rec: :bro:type:`OpenFlow::Info`)

   Event that can be handled to access the :bro:type:`OpenFlow::Info`
   record as it is sent on to the logging framework.

Functions
#########
.. bro:id:: OpenFlow::log_new

   :Type: :bro:type:`function` (dpid: :bro:type:`count`, success_event: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`) : :bro:type:`OpenFlow::Controller`

   Log controller constructor.
   

   :dpid: OpenFlow switch datapath id.
   

   :success_event: If true, flow_mod_success is raised for each logged line.
   

   :returns: OpenFlow::Controller record.


