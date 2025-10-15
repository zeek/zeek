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
=============================================================================== =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                                         
                                                                                
                                                                                * :zeek:enum:`OpenFlow::LOG`
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                                
                                                                                :New Fields: :zeek:type:`OpenFlow::ControllerState`
                                                                                
                                                                                  log_dpid: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                    OpenFlow switch datapath id.
                                                                                
                                                                                  log_success_event: :zeek:type:`bool` :zeek:attr:`&optional`
                                                                                    Raise or do not raise success event.
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
                                                                                
                                                                                * :zeek:enum:`OpenFlow::OFLOG`
=============================================================================== =============================================================

Events
######
===================================================== ===================================================================
:zeek:id:`OpenFlow::log_openflow`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`OpenFlow::Info`
                                                      record as it is sent on to the logging framework.
===================================================== ===================================================================

Hooks
#####
============================================================= =
:zeek:id:`OpenFlow::log_policy`: :zeek:type:`Log::PolicyHook` 
============================================================= =

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
   :source-code: base/frameworks/openflow/plugins/log.zeek 35 44

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
   :source-code: base/frameworks/openflow/plugins/log.zeek 48 48

   :Type: :zeek:type:`event` (rec: :zeek:type:`OpenFlow::Info`)

   Event that can be handled to access the :zeek:type:`OpenFlow::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: OpenFlow::log_policy
   :source-code: base/frameworks/openflow/plugins/log.zeek 16 16

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: OpenFlow::log_new
   :source-code: base/frameworks/openflow/plugins/log.zeek 70 78

   :Type: :zeek:type:`function` (dpid: :zeek:type:`count`, success_event: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`OpenFlow::Controller`

   Log controller constructor.
   

   :param dpid: OpenFlow switch datapath id.
   

   :param success_event: If true, flow_mod_success is raised for each logged line.
   

   :returns: OpenFlow::Controller record.


