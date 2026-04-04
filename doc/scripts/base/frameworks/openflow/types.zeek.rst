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


   .. zeek:field:: state :zeek:type:`OpenFlow::ControllerState`

      Controller related state.


   .. zeek:field:: supports_flow_removed :zeek:type:`bool`

      Does the controller support the flow_removed event?


   .. zeek:field:: describe :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`string`

      Function that describes the controller. Has to be implemented.


   .. zeek:field:: init :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`void` :zeek:attr:`&optional`

      One-time initialization function. If defined, controller_init_done has to be called once initialization finishes.


   .. zeek:field:: destroy :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`void` :zeek:attr:`&optional`

      One-time destruction function.


   .. zeek:field:: flow_mod :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`) : :zeek:type:`bool` :zeek:attr:`&optional`

      flow_mod function.


   .. zeek:field:: flow_clear :zeek:type:`function` (state: :zeek:type:`OpenFlow::ControllerState`) : :zeek:type:`bool` :zeek:attr:`&optional`

      flow_clear function.


   Controller record representing an openflow controller.

.. zeek:type:: OpenFlow::ControllerState
   :source-code: base/frameworks/openflow/types.zeek 17 24

   :Type: :zeek:type:`record`


   .. zeek:field:: _plugin :zeek:type:`OpenFlow::Plugin` :zeek:attr:`&optional`

      Internally set to the type of plugin used.


   .. zeek:field:: _name :zeek:type:`string` :zeek:attr:`&optional`

      Internally set to the unique name of the controller.


   .. zeek:field:: _activated :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Internally set to true once the controller is activated.


   .. zeek:field:: ryu_host :zeek:type:`addr` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

      Controller ip.


   .. zeek:field:: ryu_port :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

      Controller listen port.


   .. zeek:field:: ryu_dpid :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

      OpenFlow switch datapath id.


   .. zeek:field:: ryu_debug :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/ryu.zeek` is loaded)

      Enable debug mode - output JSON to stdout; do not perform actions.


   .. zeek:field:: log_dpid :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

      OpenFlow switch datapath id.


   .. zeek:field:: log_success_event :zeek:type:`bool` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)

      Raise or do not raise success event.


   .. zeek:field:: broker_host :zeek:type:`addr` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

      Controller ip.


   .. zeek:field:: broker_port :zeek:type:`port` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

      Controller listen port.


   .. zeek:field:: broker_dpid :zeek:type:`count` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/frameworks/openflow/plugins/broker.zeek` is loaded)

      OpenFlow switch datapath id.


   .. zeek:field:: broker_topic :zeek:type:`string` :zeek:attr:`&optional`

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


   .. zeek:field:: out_ports :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Output ports to send data to.


   .. zeek:field:: vlan_vid :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set vlan vid to this value.


   .. zeek:field:: vlan_pcp :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set vlan priority to this value.


   .. zeek:field:: vlan_strip :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Strip vlan tag.


   .. zeek:field:: dl_src :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set ethernet source address.


   .. zeek:field:: dl_dst :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set ethernet destination address.


   .. zeek:field:: nw_tos :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set ip tos to this value.


   .. zeek:field:: nw_src :zeek:type:`addr` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set source to this ip.


   .. zeek:field:: nw_dst :zeek:type:`addr` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set destination to this ip.


   .. zeek:field:: tp_src :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set tcp/udp source port.


   .. zeek:field:: tp_dst :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Set tcp/udp destination port.

   :Attributes: :zeek:attr:`&log`

   The actions that can be taken in a flow.
   (Separate record to make ofp_flow_mod less crowded)

.. zeek:type:: OpenFlow::ofp_flow_mod
   :source-code: base/frameworks/openflow/types.zeek 88 113

   :Type: :zeek:type:`record`


   .. zeek:field:: cookie :zeek:type:`count` :zeek:attr:`&log`

      Opaque controller-issued identifier.


   .. zeek:field:: table_id :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Table to put the flow in. OFPTT_ALL can be used for delete,
      to delete flows from all matching tables.


   .. zeek:field:: command :zeek:type:`OpenFlow::ofp_flow_mod_command` :zeek:attr:`&log`

      One of OFPFC_*.


   .. zeek:field:: idle_timeout :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Idle time before discarding (seconds).


   .. zeek:field:: hard_timeout :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Max time before discarding (seconds).


   .. zeek:field:: priority :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Priority level of flow entry.


   .. zeek:field:: out_port :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      For OFPFC_DELETE* commands, require matching entry to include
      this as an output port/group. OFPP_ANY/OFPG_ANY means no restrictions.


   .. zeek:field:: out_group :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: flags :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Bitmap of the OFPFF_* flags


   .. zeek:field:: actions :zeek:type:`OpenFlow::ofp_flow_action` :zeek:attr:`&default` = *...* :zeek:attr:`&optional` :zeek:attr:`&log`

      Actions to take on match

   :Attributes: :zeek:attr:`&log`

   Openflow flow_mod definition, describing the action to perform.

.. zeek:type:: OpenFlow::ofp_match
   :source-code: base/frameworks/openflow/types.zeek 31 58

   :Type: :zeek:type:`record`


   .. zeek:field:: in_port :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: dl_src :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: dl_dst :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: dl_vlan :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: dl_vlan_pcp :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: dl_type :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: nw_tos :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: nw_proto :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: nw_src :zeek:type:`subnet` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: nw_dst :zeek:type:`subnet` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: tp_src :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: tp_dst :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

   :Attributes: :zeek:attr:`&log`

   Openflow match definition.

   The openflow match record describes
   which packets match to a specific
   rule in a flow table.


