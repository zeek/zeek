:tocdepth: 3

base/frameworks/openflow/types.zeek
===================================
.. zeek:namespace:: OpenFlow

Types used by the OpenFlow framework.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow/consts.zeek </scripts/base/frameworks/openflow/consts.zeek>`

Summary
~~~~~~~
Types
#####
=============================================================================== ===============================================================
:zeek:type:`OpenFlow::Controller`: :zeek:type:`record`                          Controller record representing an openflow controller.
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` Controller related state.
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                Available openflow plugins.
:zeek:type:`OpenFlow::ofp_flow_action`: :zeek:type:`record` :zeek:attr:`&log`   The actions that can be taken in a flow.
:zeek:type:`OpenFlow::ofp_flow_mod`: :zeek:type:`record` :zeek:attr:`&log`      Openflow flow_mod definition, describing the action to perform.
:zeek:type:`OpenFlow::ofp_match`: :zeek:type:`record` :zeek:attr:`&log`         Openflow match definition.
=============================================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: OpenFlow::Controller
   :source-code: base/frameworks/openflow/types.zeek 116 131

   :Type: :zeek:type:`record`

      state: :zeek:type:`OpenFlow::ControllerState`
         Controller related state.

      supports_flow_removed: :zeek:type:`bool`
         Does the controller support the flow_removed event?

      describe: :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`string`
         Function that describes the controller. Has to be implemented.

      init: :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`void` :zeek:attr:`&optional`
         One-time initialization function. If defined, controller_init_done has to be called once initialization finishes.

      destroy: :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`void` :zeek:attr:`&optional`
         One-time destruction function.

      flow_mod: :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`) : :zeek:type:`bool` :zeek:attr:`&optional`
         flow_mod function.

      flow_clear: :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`bool` :zeek:attr:`&optional`
         flow_clear function.

   Controller record representing an openflow controller.

.. zeek:type:: OpenFlow::ControllerState
   :source-code: base/frameworks/openflow/types.zeek 17 24

   :Type: :zeek:type:`record`

      _plugin: :zeek:type:`OpenFlow::Plugin` :zeek:attr:`&optional`
         Internally set to the type of plugin used.

      _name: :zeek:type:`string` :zeek:attr:`&optional`
         Internally set to the unique name of the controller.

      _activated: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Internally set to true once the controller is activated.

      ryu_host: :zeek:type:`addr` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Controller ip.

      ryu_port: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Controller listen port.

      ryu_dpid: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         OpenFlow switch datapath id.

      ryu_debug: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Enable debug mode - output JSON to stdout; do not perform actions.

      log_dpid: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

         OpenFlow switch datapath id.

      log_success_event: :zeek:type:`bool` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

         Raise or do not raise success event.

      broker_host: :zeek:type:`addr` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Controller ip.

      broker_port: :zeek:type:`port` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Controller listen port.

      broker_dpid: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         OpenFlow switch datapath id.

      broker_topic: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Topic to send events for this controller to.
   :Attributes: :zeek:attr:`&redef`

   Controller related state.
   Can be redefined by plugins to
   add state.

.. zeek:type:: OpenFlow::Plugin
   :source-code: base/frameworks/openflow/types.zeek 9 13

   :Type: :zeek:type:`enum`

      .. zeek:enum:: OpenFlow::INVALID OpenFlow::Plugin

         Internal placeholder plugin.

      .. zeek:enum:: OpenFlow::RYU OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)


      .. zeek:enum:: OpenFlow::OFLOG OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)


      .. zeek:enum:: OpenFlow::BROKER OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)


   Available openflow plugins.

.. zeek:type:: OpenFlow::ofp_flow_action
   :source-code: base/frameworks/openflow/types.zeek 62 85

   :Type: :zeek:type:`record`

      out_ports: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Output ports to send data to.

      vlan_vid: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set vlan vid to this value.

      vlan_pcp: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set vlan priority to this value.

      vlan_strip: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Strip vlan tag.

      dl_src: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set ethernet source address.

      dl_dst: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set ethernet destination address.

      nw_tos: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set ip tos to this value.

      nw_src: :zeek:type:`addr` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set source to this ip.

      nw_dst: :zeek:type:`addr` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set destination to this ip.

      tp_src: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set tcp/udp source port.

      tp_dst: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Set tcp/udp destination port.
   :Attributes: :zeek:attr:`&log`

   The actions that can be taken in a flow.
   (Separate record to make ofp_flow_mod less crowded)

.. zeek:type:: OpenFlow::ofp_flow_mod
   :source-code: base/frameworks/openflow/types.zeek 88 113

   :Type: :zeek:type:`record`

      cookie: :zeek:type:`count` :zeek:attr:`&log`
         Opaque controller-issued identifier.

      table_id: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Table to put the flow in. OFPTT_ALL can be used for delete,
         to delete flows from all matching tables.

      command: :zeek:type:`OpenFlow::ofp_flow_mod_command` :zeek:attr:`&log`
         One of OFPFC_*.

      idle_timeout: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Idle time before discarding (seconds).

      hard_timeout: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Max time before discarding (seconds).

      priority: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Priority level of flow entry.

      out_port: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         For OFPFC_DELETE* commands, require matching entry to include
         this as an output port/group. OFPP_ANY/OFPG_ANY means no restrictions.

      out_group: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      flags: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Bitmap of the OFPFF_* flags

      actions: :zeek:type:`OpenFlow::ofp_flow_action` :zeek:attr:`&default` = *[out_ports=[], vlan_vid=<uninitialized>, vlan_pcp=<uninitialized>, vlan_strip=F, dl_src=<uninitialized>, dl_dst=<uninitialized>, nw_tos=<uninitialized>, nw_src=<uninitialized>, nw_dst=<uninitialized>, tp_src=<uninitialized>, tp_dst=<uninitialized>]* :zeek:attr:`&optional` :zeek:attr:`&log`
         Actions to take on match
   :Attributes: :zeek:attr:`&log`

   Openflow flow_mod definition, describing the action to perform.

.. zeek:type:: OpenFlow::ofp_match
   :source-code: base/frameworks/openflow/types.zeek 31 58

   :Type: :zeek:type:`record`

      in_port: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      dl_src: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      dl_dst: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      dl_vlan: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      dl_vlan_pcp: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      dl_type: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      nw_tos: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      nw_proto: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      nw_src: :zeek:type:`subnet` :zeek:attr:`&optional` :zeek:attr:`&log`

      nw_dst: :zeek:type:`subnet` :zeek:attr:`&optional` :zeek:attr:`&log`

      tp_src: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      tp_dst: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
   :Attributes: :zeek:attr:`&log`

   Openflow match definition.
   
   The openflow match record describes
   which packets match to a specific
   rule in a flow table.


