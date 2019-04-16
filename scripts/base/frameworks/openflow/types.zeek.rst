:tocdepth: 3

base/frameworks/openflow/types.zeek
===================================
.. bro:namespace:: OpenFlow

Types used by the OpenFlow framework.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow/consts.zeek </scripts/base/frameworks/openflow/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================================================ ===============================================================
:bro:type:`OpenFlow::Controller`: :bro:type:`record`                         Controller record representing an openflow controller.
:bro:type:`OpenFlow::ControllerState`: :bro:type:`record` :bro:attr:`&redef` Controller related state.
:bro:type:`OpenFlow::Plugin`: :bro:type:`enum`                               Available openflow plugins.
:bro:type:`OpenFlow::ofp_flow_action`: :bro:type:`record` :bro:attr:`&log`   The actions that can be taken in a flow.
:bro:type:`OpenFlow::ofp_flow_mod`: :bro:type:`record` :bro:attr:`&log`      Openflow flow_mod definition, describing the action to perform.
:bro:type:`OpenFlow::ofp_match`: :bro:type:`record` :bro:attr:`&log`         Openflow match definition.
============================================================================ ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: OpenFlow::Controller

   :Type: :bro:type:`record`

      state: :bro:type:`OpenFlow::ControllerState`
         Controller related state.

      supports_flow_removed: :bro:type:`bool`
         Does the controller support the flow_removed event?

      describe: :bro:type:`function` (state: :bro:type:`OpenFlow::ControllerState`) : :bro:type:`string`
         Function that describes the controller. Has to be implemented.

      init: :bro:type:`function` (state: :bro:type:`OpenFlow::ControllerState`) : :bro:type:`void` :bro:attr:`&optional`
         One-time initialization function. If defined, controller_init_done has to be called once initialization finishes.

      destroy: :bro:type:`function` (state: :bro:type:`OpenFlow::ControllerState`) : :bro:type:`void` :bro:attr:`&optional`
         One-time destruction function.

      flow_mod: :bro:type:`function` (state: :bro:type:`OpenFlow::ControllerState`, match: :bro:type:`OpenFlow::ofp_match`, flow_mod: :bro:type:`OpenFlow::ofp_flow_mod`) : :bro:type:`bool` :bro:attr:`&optional`
         flow_mod function.

      flow_clear: :bro:type:`function` (state: :bro:type:`OpenFlow::ControllerState`) : :bro:type:`bool` :bro:attr:`&optional`
         flow_clear function.

   Controller record representing an openflow controller.

.. bro:type:: OpenFlow::ControllerState

   :Type: :bro:type:`record`

      _plugin: :bro:type:`OpenFlow::Plugin` :bro:attr:`&optional`
         Internally set to the type of plugin used.

      _name: :bro:type:`string` :bro:attr:`&optional`
         Internally set to the unique name of the controller.

      _activated: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Internally set to true once the controller is activated.

      ryu_host: :bro:type:`addr` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Controller ip.

      ryu_port: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Controller listen port.

      ryu_dpid: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         OpenFlow switch datapath id.

      ryu_debug: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

         Enable debug mode - output JSON to stdout; do not perform actions.

      log_dpid: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

         OpenFlow switch datapath id.

      log_success_event: :bro:type:`bool` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

         Raise or do not raise success event.

      broker_host: :bro:type:`addr` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Controller ip.

      broker_port: :bro:type:`port` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Controller listen port.

      broker_dpid: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         OpenFlow switch datapath id.

      broker_topic: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

         Topic to send events for this controller to.
   :Attributes: :bro:attr:`&redef`

   Controller related state.
   Can be redefined by plugins to
   add state.

.. bro:type:: OpenFlow::Plugin

   :Type: :bro:type:`enum`

      .. bro:enum:: OpenFlow::INVALID OpenFlow::Plugin

         Internal placeholder plugin.

      .. bro:enum:: OpenFlow::RYU OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)


      .. bro:enum:: OpenFlow::OFLOG OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)


      .. bro:enum:: OpenFlow::BROKER OpenFlow::Plugin

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)


   Available openflow plugins.

.. bro:type:: OpenFlow::ofp_flow_action

   :Type: :bro:type:`record`

      out_ports: :bro:type:`vector` of :bro:type:`count` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional` :bro:attr:`&log`
         Output ports to send data to.

      vlan_vid: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Set vlan vid to this value.

      vlan_pcp: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Set vlan priority to this value.

      vlan_strip: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional` :bro:attr:`&log`
         Strip vlan tag.

      dl_src: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Set ethernet source address.

      dl_dst: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Set ethernet destination address.

      nw_tos: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Set ip tos to this value.

      nw_src: :bro:type:`addr` :bro:attr:`&optional` :bro:attr:`&log`
         Set source to this ip.

      nw_dst: :bro:type:`addr` :bro:attr:`&optional` :bro:attr:`&log`
         Set destination to this ip.

      tp_src: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Set tcp/udp source port.

      tp_dst: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Set tcp/udp destination port.
   :Attributes: :bro:attr:`&log`

   The actions that can be taken in a flow.
   (Separate record to make ofp_flow_mod less crowded)

.. bro:type:: OpenFlow::ofp_flow_mod

   :Type: :bro:type:`record`

      cookie: :bro:type:`count` :bro:attr:`&log`
         Opaque controller-issued identifier.

      table_id: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Table to put the flow in. OFPTT_ALL can be used for delete,
         to delete flows from all matching tables.

      command: :bro:type:`OpenFlow::ofp_flow_mod_command` :bro:attr:`&log`
         One of OFPFC_*.

      idle_timeout: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional` :bro:attr:`&log`
         Idle time before discarding (seconds).

      hard_timeout: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional` :bro:attr:`&log`
         Max time before discarding (seconds).

      priority: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional` :bro:attr:`&log`
         Priority level of flow entry.

      out_port: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         For OFPFC_DELETE* commands, require matching entried to include
         this as an output port/group. OFPP_ANY/OFPG_ANY means no restrictions.

      out_group: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      flags: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional` :bro:attr:`&log`
         Bitmap of the OFPFF_* flags

      actions: :bro:type:`OpenFlow::ofp_flow_action` :bro:attr:`&default` = ``[out_ports=[], vlan_vid=<uninitialized>, vlan_pcp=<uninitialized>, vlan_strip=F, dl_src=<uninitialized>, dl_dst=<uninitialized>, nw_tos=<uninitialized>, nw_src=<uninitialized>, nw_dst=<uninitialized>, tp_src=<uninitialized>, tp_dst=<uninitialized>]`` :bro:attr:`&optional` :bro:attr:`&log`
         Actions to take on match
   :Attributes: :bro:attr:`&log`

   Openflow flow_mod definition, describing the action to perform.

.. bro:type:: OpenFlow::ofp_match

   :Type: :bro:type:`record`

      in_port: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      dl_src: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`

      dl_dst: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`

      dl_vlan: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      dl_vlan_pcp: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      dl_type: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      nw_tos: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      nw_proto: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      nw_src: :bro:type:`subnet` :bro:attr:`&optional` :bro:attr:`&log`

      nw_dst: :bro:type:`subnet` :bro:attr:`&optional` :bro:attr:`&log`

      tp_src: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`

      tp_dst: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
   :Attributes: :bro:attr:`&log`

   Openflow match definition.
   
   The openflow match record describes
   which packets match to a specific
   rule in a flow table.


