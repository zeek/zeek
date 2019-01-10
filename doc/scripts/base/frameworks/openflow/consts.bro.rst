:tocdepth: 3

base/frameworks/openflow/consts.bro
===================================
.. bro:namespace:: OpenFlow

Constants used by the OpenFlow framework.

:Namespace: OpenFlow

Summary
~~~~~~~
Constants
#########
============================================================= ======================================================================
:bro:id:`OpenFlow::ETH_APPLETALK`: :bro:type:`count`          
:bro:id:`OpenFlow::ETH_APPLETALK_ARP`: :bro:type:`count`      
:bro:id:`OpenFlow::ETH_ARP`: :bro:type:`count`                
:bro:id:`OpenFlow::ETH_EAP_OVER_LAN`: :bro:type:`count`       
:bro:id:`OpenFlow::ETH_ETHER_FLOW_CONTROL`: :bro:type:`count` 
:bro:id:`OpenFlow::ETH_IPX`: :bro:type:`count`                
:bro:id:`OpenFlow::ETH_IPX_OLD`: :bro:type:`count`            
:bro:id:`OpenFlow::ETH_IPv4`: :bro:type:`count`               
:bro:id:`OpenFlow::ETH_IPv6`: :bro:type:`count`               
:bro:id:`OpenFlow::ETH_JUMBO_FRAMES`: :bro:type:`count`       
:bro:id:`OpenFlow::ETH_MAC_SECURITY`: :bro:type:`count`       
:bro:id:`OpenFlow::ETH_MPLS_MULTICAST`: :bro:type:`count`     
:bro:id:`OpenFlow::ETH_MPLS_UNICAST`: :bro:type:`count`       
:bro:id:`OpenFlow::ETH_PPPOE_DISCOVERY`: :bro:type:`count`    
:bro:id:`OpenFlow::ETH_PPPOE_SESSION`: :bro:type:`count`      
:bro:id:`OpenFlow::ETH_PROVIDER_BRIDING`: :bro:type:`count`   
:bro:id:`OpenFlow::ETH_QINQ`: :bro:type:`count`               
:bro:id:`OpenFlow::ETH_RARP`: :bro:type:`count`               
:bro:id:`OpenFlow::ETH_VLAN`: :bro:type:`count`               
:bro:id:`OpenFlow::ETH_WOL`: :bro:type:`count`                
:bro:id:`OpenFlow::INVALID_COOKIE`: :bro:type:`count`         Return value for a cookie from a flow
                                                              which is not added, modified or deleted
                                                              from the bro openflow framework.
:bro:id:`OpenFlow::IP_CBT`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_EGP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_ETHERIP`: :bro:type:`count`             
:bro:id:`OpenFlow::IP_FC`: :bro:type:`count`                  
:bro:id:`OpenFlow::IP_GGP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_GRE`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_HOPOPT`: :bro:type:`count`              
:bro:id:`OpenFlow::IP_ICMP`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_IGMP`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_IGP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_IPIP`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_IPv6`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_ISIS`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_L2TP`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_MPLS`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_MTP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_OSPF`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_RDP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_RSVP`: :bro:type:`count`                
:bro:id:`OpenFlow::IP_ST`: :bro:type:`count`                  
:bro:id:`OpenFlow::IP_TCP`: :bro:type:`count`                 
:bro:id:`OpenFlow::IP_UDP`: :bro:type:`count`                 
:bro:id:`OpenFlow::OFPFF_CHECK_OVERLAP`: :bro:type:`count`    Check for overlapping entries first.
:bro:id:`OpenFlow::OFPFF_EMERG`: :bro:type:`count`            Remark this is for emergency.
:bro:id:`OpenFlow::OFPFF_SEND_FLOW_REM`: :bro:type:`count`    Send flow removed message when flow
                                                              expires or is deleted.
:bro:id:`OpenFlow::OFPP_ALL`: :bro:type:`count`               All physical ports except input port.
:bro:id:`OpenFlow::OFPP_ANY`: :bro:type:`count`               Wildcard port used only for flow mod (delete) and flow stats requests.
:bro:id:`OpenFlow::OFPP_CONTROLLER`: :bro:type:`count`        Send to controller.
:bro:id:`OpenFlow::OFPP_FLOOD`: :bro:type:`count`             All physical ports except input port and
                                                              those disabled by STP.
:bro:id:`OpenFlow::OFPP_IN_PORT`: :bro:type:`count`           Send the packet out the input port.
:bro:id:`OpenFlow::OFPP_LOCAL`: :bro:type:`count`             Local openflow "port".
:bro:id:`OpenFlow::OFPP_NORMAL`: :bro:type:`count`            Process with normal L2/L3 switching.
:bro:id:`OpenFlow::OFPP_TABLE`: :bro:type:`count`             Perform actions in flow table.
:bro:id:`OpenFlow::OFPTT_ALL`: :bro:type:`count`              
:bro:id:`OpenFlow::OFP_NO_BUFFER`: :bro:type:`count`          
============================================================= ======================================================================

Types
#####
============================================================ ======================================
:bro:type:`OpenFlow::ofp_action_type`: :bro:type:`enum`      Openflow action_type definitions.
:bro:type:`OpenFlow::ofp_config_flags`: :bro:type:`enum`     Openflow config flag definitions.
:bro:type:`OpenFlow::ofp_flow_mod_command`: :bro:type:`enum` Openflow flow_mod_command definitions.
============================================================ ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: OpenFlow::ETH_APPLETALK

   :Type: :bro:type:`count`
   :Default: ``32923``


.. bro:id:: OpenFlow::ETH_APPLETALK_ARP

   :Type: :bro:type:`count`
   :Default: ``33011``


.. bro:id:: OpenFlow::ETH_ARP

   :Type: :bro:type:`count`
   :Default: ``2054``


.. bro:id:: OpenFlow::ETH_EAP_OVER_LAN

   :Type: :bro:type:`count`
   :Default: ``34958``


.. bro:id:: OpenFlow::ETH_ETHER_FLOW_CONTROL

   :Type: :bro:type:`count`
   :Default: ``34824``


.. bro:id:: OpenFlow::ETH_IPX

   :Type: :bro:type:`count`
   :Default: ``33080``


.. bro:id:: OpenFlow::ETH_IPX_OLD

   :Type: :bro:type:`count`
   :Default: ``33079``


.. bro:id:: OpenFlow::ETH_IPv4

   :Type: :bro:type:`count`
   :Default: ``2048``


.. bro:id:: OpenFlow::ETH_IPv6

   :Type: :bro:type:`count`
   :Default: ``34525``


.. bro:id:: OpenFlow::ETH_JUMBO_FRAMES

   :Type: :bro:type:`count`
   :Default: ``34928``


.. bro:id:: OpenFlow::ETH_MAC_SECURITY

   :Type: :bro:type:`count`
   :Default: ``35045``


.. bro:id:: OpenFlow::ETH_MPLS_MULTICAST

   :Type: :bro:type:`count`
   :Default: ``34888``


.. bro:id:: OpenFlow::ETH_MPLS_UNICAST

   :Type: :bro:type:`count`
   :Default: ``34887``


.. bro:id:: OpenFlow::ETH_PPPOE_DISCOVERY

   :Type: :bro:type:`count`
   :Default: ``34915``


.. bro:id:: OpenFlow::ETH_PPPOE_SESSION

   :Type: :bro:type:`count`
   :Default: ``34916``


.. bro:id:: OpenFlow::ETH_PROVIDER_BRIDING

   :Type: :bro:type:`count`
   :Default: ``34984``


.. bro:id:: OpenFlow::ETH_QINQ

   :Type: :bro:type:`count`
   :Default: ``37120``


.. bro:id:: OpenFlow::ETH_RARP

   :Type: :bro:type:`count`
   :Default: ``32821``


.. bro:id:: OpenFlow::ETH_VLAN

   :Type: :bro:type:`count`
   :Default: ``33024``


.. bro:id:: OpenFlow::ETH_WOL

   :Type: :bro:type:`count`
   :Default: ``2114``


.. bro:id:: OpenFlow::INVALID_COOKIE

   :Type: :bro:type:`count`
   :Default: ``18446744073709551615``

   Return value for a cookie from a flow
   which is not added, modified or deleted
   from the bro openflow framework.

.. bro:id:: OpenFlow::IP_CBT

   :Type: :bro:type:`count`
   :Default: ``7``


.. bro:id:: OpenFlow::IP_EGP

   :Type: :bro:type:`count`
   :Default: ``8``


.. bro:id:: OpenFlow::IP_ETHERIP

   :Type: :bro:type:`count`
   :Default: ``97``


.. bro:id:: OpenFlow::IP_FC

   :Type: :bro:type:`count`
   :Default: ``133``


.. bro:id:: OpenFlow::IP_GGP

   :Type: :bro:type:`count`
   :Default: ``3``


.. bro:id:: OpenFlow::IP_GRE

   :Type: :bro:type:`count`
   :Default: ``47``


.. bro:id:: OpenFlow::IP_HOPOPT

   :Type: :bro:type:`count`
   :Default: ``0``


.. bro:id:: OpenFlow::IP_ICMP

   :Type: :bro:type:`count`
   :Default: ``1``


.. bro:id:: OpenFlow::IP_IGMP

   :Type: :bro:type:`count`
   :Default: ``2``


.. bro:id:: OpenFlow::IP_IGP

   :Type: :bro:type:`count`
   :Default: ``9``


.. bro:id:: OpenFlow::IP_IPIP

   :Type: :bro:type:`count`
   :Default: ``4``


.. bro:id:: OpenFlow::IP_IPv6

   :Type: :bro:type:`count`
   :Default: ``41``


.. bro:id:: OpenFlow::IP_ISIS

   :Type: :bro:type:`count`
   :Default: ``124``


.. bro:id:: OpenFlow::IP_L2TP

   :Type: :bro:type:`count`
   :Default: ``115``


.. bro:id:: OpenFlow::IP_MPLS

   :Type: :bro:type:`count`
   :Default: ``137``


.. bro:id:: OpenFlow::IP_MTP

   :Type: :bro:type:`count`
   :Default: ``92``


.. bro:id:: OpenFlow::IP_OSPF

   :Type: :bro:type:`count`
   :Default: ``89``


.. bro:id:: OpenFlow::IP_RDP

   :Type: :bro:type:`count`
   :Default: ``27``


.. bro:id:: OpenFlow::IP_RSVP

   :Type: :bro:type:`count`
   :Default: ``46``


.. bro:id:: OpenFlow::IP_ST

   :Type: :bro:type:`count`
   :Default: ``5``


.. bro:id:: OpenFlow::IP_TCP

   :Type: :bro:type:`count`
   :Default: ``6``


.. bro:id:: OpenFlow::IP_UDP

   :Type: :bro:type:`count`
   :Default: ``17``


.. bro:id:: OpenFlow::OFPFF_CHECK_OVERLAP

   :Type: :bro:type:`count`
   :Default: ``2``

   Check for overlapping entries first.

.. bro:id:: OpenFlow::OFPFF_EMERG

   :Type: :bro:type:`count`
   :Default: ``4``

   Remark this is for emergency.
   Flows added with this are only used
   when the controller is disconnected.

.. bro:id:: OpenFlow::OFPFF_SEND_FLOW_REM

   :Type: :bro:type:`count`
   :Default: ``1``

   Send flow removed message when flow
   expires or is deleted.

.. bro:id:: OpenFlow::OFPP_ALL

   :Type: :bro:type:`count`
   :Default: ``4294967292``

   All physical ports except input port.

.. bro:id:: OpenFlow::OFPP_ANY

   :Type: :bro:type:`count`
   :Default: ``4294967295``

   Wildcard port used only for flow mod (delete) and flow stats requests.

.. bro:id:: OpenFlow::OFPP_CONTROLLER

   :Type: :bro:type:`count`
   :Default: ``4294967293``

   Send to controller.

.. bro:id:: OpenFlow::OFPP_FLOOD

   :Type: :bro:type:`count`
   :Default: ``4294967291``

   All physical ports except input port and
   those disabled by STP.

.. bro:id:: OpenFlow::OFPP_IN_PORT

   :Type: :bro:type:`count`
   :Default: ``4294967288``

   Send the packet out the input port. This
   virual port must be explicitly used in
   order to send back out of the input port.

.. bro:id:: OpenFlow::OFPP_LOCAL

   :Type: :bro:type:`count`
   :Default: ``4294967294``

   Local openflow "port".

.. bro:id:: OpenFlow::OFPP_NORMAL

   :Type: :bro:type:`count`
   :Default: ``4294967290``

   Process with normal L2/L3 switching.

.. bro:id:: OpenFlow::OFPP_TABLE

   :Type: :bro:type:`count`
   :Default: ``4294967289``

   Perform actions in flow table.
   NB: This can only be the destination port
   for packet-out messages.

.. bro:id:: OpenFlow::OFPTT_ALL

   :Type: :bro:type:`count`
   :Default: ``255``


.. bro:id:: OpenFlow::OFP_NO_BUFFER

   :Type: :bro:type:`count`
   :Default: ``4294967295``


Types
#####
.. bro:type:: OpenFlow::ofp_action_type

   :Type: :bro:type:`enum`

      .. bro:enum:: OpenFlow::OFPAT_OUTPUT OpenFlow::ofp_action_type

         Output to switch port.

      .. bro:enum:: OpenFlow::OFPAT_SET_VLAN_VID OpenFlow::ofp_action_type

         Set the 802.1q VLAN id.

      .. bro:enum:: OpenFlow::OFPAT_SET_VLAN_PCP OpenFlow::ofp_action_type

         Set the 802.1q priority.

      .. bro:enum:: OpenFlow::OFPAT_STRIP_VLAN OpenFlow::ofp_action_type

         Strip the 802.1q header.

      .. bro:enum:: OpenFlow::OFPAT_SET_DL_SRC OpenFlow::ofp_action_type

         Ethernet source address.

      .. bro:enum:: OpenFlow::OFPAT_SET_DL_DST OpenFlow::ofp_action_type

         Ethernet destination address.

      .. bro:enum:: OpenFlow::OFPAT_SET_NW_SRC OpenFlow::ofp_action_type

         IP source address.

      .. bro:enum:: OpenFlow::OFPAT_SET_NW_DST OpenFlow::ofp_action_type

         IP destination address.

      .. bro:enum:: OpenFlow::OFPAT_SET_NW_TOS OpenFlow::ofp_action_type

         IP ToS (DSCP field, 6 bits).

      .. bro:enum:: OpenFlow::OFPAT_SET_TP_SRC OpenFlow::ofp_action_type

         TCP/UDP source port.

      .. bro:enum:: OpenFlow::OFPAT_SET_TP_DST OpenFlow::ofp_action_type

         TCP/UDP destination port.

      .. bro:enum:: OpenFlow::OFPAT_ENQUEUE OpenFlow::ofp_action_type

         Output to queue.

      .. bro:enum:: OpenFlow::OFPAT_VENDOR OpenFlow::ofp_action_type

         Vendor specific.

   Openflow action_type definitions.
   
   The openflow action type defines
   what actions openflow can take
   to modify a packet

.. bro:type:: OpenFlow::ofp_config_flags

   :Type: :bro:type:`enum`

      .. bro:enum:: OpenFlow::OFPC_FRAG_NORMAL OpenFlow::ofp_config_flags

         No special handling for fragments.

      .. bro:enum:: OpenFlow::OFPC_FRAG_DROP OpenFlow::ofp_config_flags

         Drop fragments.

      .. bro:enum:: OpenFlow::OFPC_FRAG_REASM OpenFlow::ofp_config_flags

         Reassemble (only if OFPC_IP_REASM set).

      .. bro:enum:: OpenFlow::OFPC_FRAG_MASK OpenFlow::ofp_config_flags

   Openflow config flag definitions.
   
   TODO: describe

.. bro:type:: OpenFlow::ofp_flow_mod_command

   :Type: :bro:type:`enum`

      .. bro:enum:: OpenFlow::OFPFC_ADD OpenFlow::ofp_flow_mod_command

         New flow.

      .. bro:enum:: OpenFlow::OFPFC_MODIFY OpenFlow::ofp_flow_mod_command

         Modify all matching flows.

      .. bro:enum:: OpenFlow::OFPFC_MODIFY_STRICT OpenFlow::ofp_flow_mod_command

         Modify entry strictly matching wildcards.

      .. bro:enum:: OpenFlow::OFPFC_DELETE OpenFlow::ofp_flow_mod_command

         Delete all matching flows.

      .. bro:enum:: OpenFlow::OFPFC_DELETE_STRICT OpenFlow::ofp_flow_mod_command

         Strictly matching wildcards and priority.

   Openflow flow_mod_command definitions.
   
   The openflow flow_mod_command describes
   of what kind an action is.


