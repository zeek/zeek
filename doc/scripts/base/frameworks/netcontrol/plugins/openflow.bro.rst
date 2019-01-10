:tocdepth: 3

base/frameworks/netcontrol/plugins/openflow.bro
===============================================
.. bro:namespace:: NetControl

OpenFlow plugin for the NetControl framework.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/netcontrol/main.bro </scripts/base/frameworks/netcontrol/main.bro>`, :doc:`base/frameworks/netcontrol/plugin.bro </scripts/base/frameworks/netcontrol/plugin.bro>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================= ===============================================================================
:bro:id:`NetControl::openflow_flow_timeout`: :bro:type:`interval` :bro:attr:`&redef`    The time interval after we consider a flow timed out.
:bro:id:`NetControl::openflow_message_timeout`: :bro:type:`interval` :bro:attr:`&redef` The time interval after which an openflow message is considered to be timed out
                                                                                        and we delete it from our internal tracking.
======================================================================================= ===============================================================================

Types
#####
==================================================== =================================================================================================
:bro:type:`NetControl::OfConfig`: :bro:type:`record` This record specifies the configuration that is passed to :bro:see:`NetControl::create_openflow`.
:bro:type:`NetControl::OfTable`: :bro:type:`record`  
==================================================== =================================================================================================

Redefinitions
#############
======================================================= =
:bro:type:`NetControl::PluginState`: :bro:type:`record` 
======================================================= =

Functions
#########
=========================================================== =============================================================
:bro:id:`NetControl::create_openflow`: :bro:type:`function` Instantiates an openflow plugin for the NetControl framework.
=========================================================== =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: NetControl::openflow_flow_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   The time interval after we consider a flow timed out. This should be fairly high (or
   even disabled) if you expect a lot of long flows. However, one also will have state
   buildup for quite a while if keeping this around...

.. bro:id:: NetControl::openflow_message_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20.0 secs``

   The time interval after which an openflow message is considered to be timed out
   and we delete it from our internal tracking.

Types
#####
.. bro:type:: NetControl::OfConfig

   :Type: :bro:type:`record`

      monitor: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Accept rules that target the monitor path.

      forward: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Accept rules that target the forward path.

      idle_timeout: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Default OpenFlow idle timeout.

      table_id: :bro:type:`count` :bro:attr:`&optional`
         Default OpenFlow table ID.

      priority_offset: :bro:type:`int` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Add this to all rule priorities. Can be useful if you want the openflow priorities be offset from the netcontrol priorities without having to write a filter function.

      check_pred: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`) : :bro:type:`bool` :bro:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.

      match_pred: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, e: :bro:type:`NetControl::Entity`, m: :bro:type:`vector` of :bro:type:`OpenFlow::ofp_match`) : :bro:type:`vector` of :bro:type:`OpenFlow::ofp_match` :bro:attr:`&optional`
         This predicate is called each time an OpenFlow match record is created.
         The predicate can modify the match structure before it is sent on to the
         device.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :m: The openflow match structures that were generated for this rules.
         

         :returns: The modified OpenFlow match structures that will be used in place of the structures passed in m.

      flow_mod_pred: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`, m: :bro:type:`OpenFlow::ofp_flow_mod`) : :bro:type:`OpenFlow::ofp_flow_mod` :bro:attr:`&optional`
         This predicate is called before a FlowMod message is sent to the OpenFlow
         device. It can modify the FlowMod message before it is passed on.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :m: The OpenFlow FlowMod message.
         

         :returns: The modified FlowMod message that is used in lieu of m.

   This record specifies the configuration that is passed to :bro:see:`NetControl::create_openflow`.

.. bro:type:: NetControl::OfTable

   :Type: :bro:type:`record`

      p: :bro:type:`NetControl::PluginState`

      r: :bro:type:`NetControl::Rule`

      c: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

      packet_count: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

      byte_count: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`

      duration_sec: :bro:type:`double` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`


Functions
#########
.. bro:id:: NetControl::create_openflow

   :Type: :bro:type:`function` (controller: :bro:type:`OpenFlow::Controller`, config: :bro:type:`NetControl::OfConfig` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`) : :bro:type:`NetControl::PluginState`

   Instantiates an openflow plugin for the NetControl framework.


