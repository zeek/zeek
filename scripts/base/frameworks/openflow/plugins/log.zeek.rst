:tocdepth: 3

base/frameworks/openflow/plugins/log.zeek
=========================================
.. zeek:namespace:: OpenFlow

OpenFlow plugin that outputs flow-modification commands
to a Zeek log file.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Types
#####
================================================ =================================================================
:zeek:type:`OpenFlow::Info`: :zeek:type:`record` The record type which contains column fields of the OpenFlow log.
================================================ =================================================================

Redefinitions
#############
=============================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                                         
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
=============================================================================== =

Events
######
===================================================== ===================================================================
:zeek:id:`OpenFlow::log_openflow`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`OpenFlow::Info`
                                                      record as it is sent on to the logging framework.
===================================================== ===================================================================

Functions
#########
=================================================== ===========================
:zeek:id:`OpenFlow::log_new`: :zeek:type:`function` Log controller constructor.
=================================================== ===========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: OpenFlow::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Network time.

      dpid: :zeek:type:`count` :zeek:attr:`&log`
         OpenFlow switch datapath id.

      match: :zeek:type:`OpenFlow::ofp_match` :zeek:attr:`&log`
         OpenFlow match fields.

      flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod` :zeek:attr:`&log`
         OpenFlow modify flow entry message.

   The record type which contains column fields of the OpenFlow log.

Events
######
.. zeek:id:: OpenFlow::log_openflow

   :Type: :zeek:type:`event` (rec: :zeek:type:`OpenFlow::Info`)

   Event that can be handled to access the :zeek:type:`OpenFlow::Info`
   record as it is sent on to the logging framework.

Functions
#########
.. zeek:id:: OpenFlow::log_new

   :Type: :zeek:type:`function` (dpid: :zeek:type:`count`, success_event: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`OpenFlow::Controller`

   Log controller constructor.
   

   :dpid: OpenFlow switch datapath id.
   

   :success_event: If true, flow_mod_success is raised for each logged line.
   

   :returns: OpenFlow::Controller record.


