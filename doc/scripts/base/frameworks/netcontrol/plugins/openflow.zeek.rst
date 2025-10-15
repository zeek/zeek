:tocdepth: 3

base/frameworks/netcontrol/plugins/openflow.zeek
================================================
.. zeek:namespace:: NetControl

OpenFlow plugin for the NetControl framework.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`, :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================== ===============================================================================
:zeek:id:`NetControl::openflow_flow_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`    The time interval after we consider a flow timed out.
:zeek:id:`NetControl::openflow_message_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The time interval after which an openflow message is considered to be timed out
                                                                                           and we delete it from our internal tracking.
========================================================================================== ===============================================================================

Types
#####
====================================================== ==================================================================================================
:zeek:type:`NetControl::OfConfig`: :zeek:type:`record` This record specifies the configuration that is passed to :zeek:see:`NetControl::create_openflow`.
:zeek:type:`NetControl::OfTable`: :zeek:type:`record`  
====================================================== ==================================================================================================

Redefinitions
#############
========================================================= =========================================================================
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`NetControl::PluginState`
                                                          
                                                            of_controller: :zeek:type:`OpenFlow::Controller` :zeek:attr:`&optional`
                                                              OpenFlow controller for NetControl OpenFlow plugin.
                                                          
                                                            of_config: :zeek:type:`NetControl::OfConfig` :zeek:attr:`&optional`
                                                              OpenFlow configuration record that is passed on initialization.
========================================================= =========================================================================

Functions
#########
============================================================= =============================================================
:zeek:id:`NetControl::create_openflow`: :zeek:type:`function` Instantiates an openflow plugin for the NetControl framework.
============================================================= =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: NetControl::openflow_flow_timeout
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 76 76

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The time interval after we consider a flow timed out. This should be fairly high (or
   even disabled) if you expect a lot of long flows. However, one also will have state
   buildup for quite a while if keeping this around...

.. zeek:id:: NetControl::openflow_message_timeout
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 71 71

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20.0 secs``

   The time interval after which an openflow message is considered to be timed out
   and we delete it from our internal tracking.

Types
#####
.. zeek:type:: NetControl::OfConfig
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 11 51

   :Type: :zeek:type:`record`

      monitor: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Accept rules that target the monitor path.

      forward: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Accept rules that target the forward path.

      idle_timeout: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Default OpenFlow idle timeout.

      table_id: :zeek:type:`count` :zeek:attr:`&optional`
         Default OpenFlow table ID.

      priority_offset: :zeek:type:`int` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Add this to all rule priorities. Can be useful if you want the openflow priorities be offset from the netcontrol priorities without having to write a filter function.

      check_pred: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :param p: Current plugin state.
         

         :param r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.

      match_pred: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, e: :zeek:type:`NetControl::Entity`, m: :zeek:type:`vector` of :zeek:type:`OpenFlow::ofp_match`) : :zeek:type:`vector` of :zeek:type:`OpenFlow::ofp_match` :zeek:attr:`&optional`
         This predicate is called each time an OpenFlow match record is created.
         The predicate can modify the match structure before it is sent on to the
         device.
         

         :param p: Current plugin state.
         

         :param r: The rule to be inserted or removed.
         

         :param m: The openflow match structures that were generated for this rules.
         

         :returns: The modified OpenFlow match structures that will be used in place of the structures passed in m.

      flow_mod_pred: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`, m: :zeek:type:`OpenFlow::ofp_flow_mod`) : :zeek:type:`OpenFlow::ofp_flow_mod` :zeek:attr:`&optional`
         This predicate is called before a FlowMod message is sent to the OpenFlow
         device. It can modify the FlowMod message before it is passed on.
         

         :param p: Current plugin state.
         

         :param r: The rule to be inserted or removed.
         

         :param m: The OpenFlow FlowMod message.
         

         :returns: The modified FlowMod message that is used in lieu of m.

   This record specifies the configuration that is passed to :zeek:see:`NetControl::create_openflow`.

.. zeek:type:: NetControl::OfTable
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 60 67

   :Type: :zeek:type:`record`

      p: :zeek:type:`NetControl::PluginState`

      r: :zeek:type:`NetControl::Rule`

      c: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      packet_count: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      byte_count: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      duration_sec: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`


Functions
#########
.. zeek:id:: NetControl::create_openflow
   :source-code: base/frameworks/netcontrol/plugins/openflow.zeek 448 453

   :Type: :zeek:type:`function` (controller: :zeek:type:`OpenFlow::Controller`, config: :zeek:type:`NetControl::OfConfig` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`) : :zeek:type:`NetControl::PluginState`

   Instantiates an openflow plugin for the NetControl framework.


