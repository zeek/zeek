:tocdepth: 3

base/frameworks/openflow/consts.zeek
====================================
.. zeek:namespace:: OpenFlow

Constants used by the OpenFlow framework.

:Namespace: OpenFlow

Summary
~~~~~~~
Constants
#########
=============================================================== ======================================================================
:zeek:id:`OpenFlow::ETH_APPLETALK`: :zeek:type:`count`          
:zeek:id:`OpenFlow::ETH_APPLETALK_ARP`: :zeek:type:`count`      
:zeek:id:`OpenFlow::ETH_ARP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::ETH_EAP_OVER_LAN`: :zeek:type:`count`       
:zeek:id:`OpenFlow::ETH_ETHER_FLOW_CONTROL`: :zeek:type:`count` 
:zeek:id:`OpenFlow::ETH_IPX`: :zeek:type:`count`                
:zeek:id:`OpenFlow::ETH_IPX_OLD`: :zeek:type:`count`            
:zeek:id:`OpenFlow::ETH_IPv4`: :zeek:type:`count`               
:zeek:id:`OpenFlow::ETH_IPv6`: :zeek:type:`count`               
:zeek:id:`OpenFlow::ETH_JUMBO_FRAMES`: :zeek:type:`count`       
:zeek:id:`OpenFlow::ETH_MAC_SECURITY`: :zeek:type:`count`       
:zeek:id:`OpenFlow::ETH_MPLS_MULTICAST`: :zeek:type:`count`     
:zeek:id:`OpenFlow::ETH_MPLS_UNICAST`: :zeek:type:`count`       
:zeek:id:`OpenFlow::ETH_PPPOE_DISCOVERY`: :zeek:type:`count`    
:zeek:id:`OpenFlow::ETH_PPPOE_SESSION`: :zeek:type:`count`      
:zeek:id:`OpenFlow::ETH_PROVIDER_BRIDING`: :zeek:type:`count`   
:zeek:id:`OpenFlow::ETH_QINQ`: :zeek:type:`count`               
:zeek:id:`OpenFlow::ETH_RARP`: :zeek:type:`count`               
:zeek:id:`OpenFlow::ETH_VLAN`: :zeek:type:`count`               
:zeek:id:`OpenFlow::ETH_WOL`: :zeek:type:`count`                
:zeek:id:`OpenFlow::INVALID_COOKIE`: :zeek:type:`count`         Return value for a cookie from a flow
                                                                which is not added, modified or deleted
                                                                from the bro openflow framework.
:zeek:id:`OpenFlow::IP_CBT`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_EGP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_ETHERIP`: :zeek:type:`count`             
:zeek:id:`OpenFlow::IP_FC`: :zeek:type:`count`                  
:zeek:id:`OpenFlow::IP_GGP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_GRE`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_HOPOPT`: :zeek:type:`count`              
:zeek:id:`OpenFlow::IP_ICMP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_IGMP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_IGP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_IPIP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_IPv6`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_ISIS`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_L2TP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_MPLS`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_MTP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_OSPF`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_RDP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_RSVP`: :zeek:type:`count`                
:zeek:id:`OpenFlow::IP_ST`: :zeek:type:`count`                  
:zeek:id:`OpenFlow::IP_TCP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::IP_UDP`: :zeek:type:`count`                 
:zeek:id:`OpenFlow::OFPFF_CHECK_OVERLAP`: :zeek:type:`count`    Check for overlapping entries first.
:zeek:id:`OpenFlow::OFPFF_EMERG`: :zeek:type:`count`            Remark this is for emergency.
:zeek:id:`OpenFlow::OFPFF_SEND_FLOW_REM`: :zeek:type:`count`    Send flow removed message when flow
                                                                expires or is deleted.
:zeek:id:`OpenFlow::OFPP_ALL`: :zeek:type:`count`               All physical ports except input port.
:zeek:id:`OpenFlow::OFPP_ANY`: :zeek:type:`count`               Wildcard port used only for flow mod (delete) and flow stats requests.
:zeek:id:`OpenFlow::OFPP_CONTROLLER`: :zeek:type:`count`        Send to controller.
:zeek:id:`OpenFlow::OFPP_FLOOD`: :zeek:type:`count`             All physical ports except input port and
                                                                those disabled by STP.
:zeek:id:`OpenFlow::OFPP_IN_PORT`: :zeek:type:`count`           Send the packet out the input port.
:zeek:id:`OpenFlow::OFPP_LOCAL`: :zeek:type:`count`             Local openflow "port".
:zeek:id:`OpenFlow::OFPP_NORMAL`: :zeek:type:`count`            Process with normal L2/L3 switching.
:zeek:id:`OpenFlow::OFPP_TABLE`: :zeek:type:`count`             Perform actions in flow table.
:zeek:id:`OpenFlow::OFPTT_ALL`: :zeek:type:`count`              
:zeek:id:`OpenFlow::OFP_NO_BUFFER`: :zeek:type:`count`          
=============================================================== ======================================================================

Types
#####
============================================================== ======================================
:zeek:type:`OpenFlow::ofp_action_type`: :zeek:type:`enum`      Openflow action_type definitions.
:zeek:type:`OpenFlow::ofp_config_flags`: :zeek:type:`enum`     Openflow config flag definitions.
:zeek:type:`OpenFlow::ofp_flow_mod_command`: :zeek:type:`enum` Openflow flow_mod_command definitions.
============================================================== ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: OpenFlow::ETH_APPLETALK

   :Type: :zeek:type:`count`
   :Default: ``32923``


.. zeek:id:: OpenFlow::ETH_APPLETALK_ARP

   :Type: :zeek:type:`count`
   :Default: ``33011``


.. zeek:id:: OpenFlow::ETH_ARP

   :Type: :zeek:type:`count`
   :Default: ``2054``


.. zeek:id:: OpenFlow::ETH_EAP_OVER_LAN

   :Type: :zeek:type:`count`
   :Default: ``34958``


.. zeek:id:: OpenFlow::ETH_ETHER_FLOW_CONTROL

   :Type: :zeek:type:`count`
   :Default: ``34824``


.. zeek:id:: OpenFlow::ETH_IPX

   :Type: :zeek:type:`count`
   :Default: ``33080``


.. zeek:id:: OpenFlow::ETH_IPX_OLD

   :Type: :zeek:type:`count`
   :Default: ``33079``


.. zeek:id:: OpenFlow::ETH_IPv4

   :Type: :zeek:type:`count`
   :Default: ``2048``


.. zeek:id:: OpenFlow::ETH_IPv6

   :Type: :zeek:type:`count`
   :Default: ``34525``


.. zeek:id:: OpenFlow::ETH_JUMBO_FRAMES

   :Type: :zeek:type:`count`
   :Default: ``34928``


.. zeek:id:: OpenFlow::ETH_MAC_SECURITY

   :Type: :zeek:type:`count`
   :Default: ``35045``


.. zeek:id:: OpenFlow::ETH_MPLS_MULTICAST

   :Type: :zeek:type:`count`
   :Default: ``34888``


.. zeek:id:: OpenFlow::ETH_MPLS_UNICAST

   :Type: :zeek:type:`count`
   :Default: ``34887``


.. zeek:id:: OpenFlow::ETH_PPPOE_DISCOVERY

   :Type: :zeek:type:`count`
   :Default: ``34915``


.. zeek:id:: OpenFlow::ETH_PPPOE_SESSION

   :Type: :zeek:type:`count`
   :Default: ``34916``


.. zeek:id:: OpenFlow::ETH_PROVIDER_BRIDING

   :Type: :zeek:type:`count`
   :Default: ``34984``


.. zeek:id:: OpenFlow::ETH_QINQ

   :Type: :zeek:type:`count`
   :Default: ``37120``


.. zeek:id:: OpenFlow::ETH_RARP

   :Type: :zeek:type:`count`
   :Default: ``32821``


.. zeek:id:: OpenFlow::ETH_VLAN

   :Type: :zeek:type:`count`
   :Default: ``33024``


.. zeek:id:: OpenFlow::ETH_WOL

   :Type: :zeek:type:`count`
   :Default: ``2114``


.. zeek:id:: OpenFlow::INVALID_COOKIE

   :Type: :zeek:type:`count`
   :Default: ``18446744073709551615``

   Return value for a cookie from a flow
   which is not added, modified or deleted
   from the bro openflow framework.

.. zeek:id:: OpenFlow::IP_CBT

   :Type: :zeek:type:`count`
   :Default: ``7``


.. zeek:id:: OpenFlow::IP_EGP

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: OpenFlow::IP_ETHERIP

   :Type: :zeek:type:`count`
   :Default: ``97``


.. zeek:id:: OpenFlow::IP_FC

   :Type: :zeek:type:`count`
   :Default: ``133``


.. zeek:id:: OpenFlow::IP_GGP

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: OpenFlow::IP_GRE

   :Type: :zeek:type:`count`
   :Default: ``47``


.. zeek:id:: OpenFlow::IP_HOPOPT

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: OpenFlow::IP_ICMP

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: OpenFlow::IP_IGMP

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: OpenFlow::IP_IGP

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: OpenFlow::IP_IPIP

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: OpenFlow::IP_IPv6

   :Type: :zeek:type:`count`
   :Default: ``41``


.. zeek:id:: OpenFlow::IP_ISIS

   :Type: :zeek:type:`count`
   :Default: ``124``


.. zeek:id:: OpenFlow::IP_L2TP

   :Type: :zeek:type:`count`
   :Default: ``115``


.. zeek:id:: OpenFlow::IP_MPLS

   :Type: :zeek:type:`count`
   :Default: ``137``


.. zeek:id:: OpenFlow::IP_MTP

   :Type: :zeek:type:`count`
   :Default: ``92``


.. zeek:id:: OpenFlow::IP_OSPF

   :Type: :zeek:type:`count`
   :Default: ``89``


.. zeek:id:: OpenFlow::IP_RDP

   :Type: :zeek:type:`count`
   :Default: ``27``


.. zeek:id:: OpenFlow::IP_RSVP

   :Type: :zeek:type:`count`
   :Default: ``46``


.. zeek:id:: OpenFlow::IP_ST

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: OpenFlow::IP_TCP

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: OpenFlow::IP_UDP

   :Type: :zeek:type:`count`
   :Default: ``17``


.. zeek:id:: OpenFlow::OFPFF_CHECK_OVERLAP

   :Type: :zeek:type:`count`
   :Default: ``2``

   Check for overlapping entries first.

.. zeek:id:: OpenFlow::OFPFF_EMERG

   :Type: :zeek:type:`count`
   :Default: ``4``

   Remark this is for emergency.
   Flows added with this are only used
   when the controller is disconnected.

.. zeek:id:: OpenFlow::OFPFF_SEND_FLOW_REM

   :Type: :zeek:type:`count`
   :Default: ``1``

   Send flow removed message when flow
   expires or is deleted.

.. zeek:id:: OpenFlow::OFPP_ALL

   :Type: :zeek:type:`count`
   :Default: ``4294967292``

   All physical ports except input port.

.. zeek:id:: OpenFlow::OFPP_ANY

   :Type: :zeek:type:`count`
   :Default: ``4294967295``

   Wildcard port used only for flow mod (delete) and flow stats requests.

.. zeek:id:: OpenFlow::OFPP_CONTROLLER

   :Type: :zeek:type:`count`
   :Default: ``4294967293``

   Send to controller.

.. zeek:id:: OpenFlow::OFPP_FLOOD

   :Type: :zeek:type:`count`
   :Default: ``4294967291``

   All physical ports except input port and
   those disabled by STP.

.. zeek:id:: OpenFlow::OFPP_IN_PORT

   :Type: :zeek:type:`count`
   :Default: ``4294967288``

   Send the packet out the input port. This
   virual port must be explicitly used in
   order to send back out of the input port.

.. zeek:id:: OpenFlow::OFPP_LOCAL

   :Type: :zeek:type:`count`
   :Default: ``4294967294``

   Local openflow "port".

.. zeek:id:: OpenFlow::OFPP_NORMAL

   :Type: :zeek:type:`count`
   :Default: ``4294967290``

   Process with normal L2/L3 switching.

.. zeek:id:: OpenFlow::OFPP_TABLE

   :Type: :zeek:type:`count`
   :Default: ``4294967289``

   Perform actions in flow table.
   NB: This can only be the destination port
   for packet-out messages.

.. zeek:id:: OpenFlow::OFPTT_ALL

   :Type: :zeek:type:`count`
   :Default: ``255``


.. zeek:id:: OpenFlow::OFP_NO_BUFFER

   :Type: :zeek:type:`count`
   :Default: ``4294967295``


Types
#####
.. zeek:type:: OpenFlow::ofp_action_type

   :Type: :zeek:type:`enum`

      .. zeek:enum:: OpenFlow::OFPAT_OUTPUT OpenFlow::ofp_action_type

         Output to switch port.

      .. zeek:enum:: OpenFlow::OFPAT_SET_VLAN_VID OpenFlow::ofp_action_type

         Set the 802.1q VLAN id.

      .. zeek:enum:: OpenFlow::OFPAT_SET_VLAN_PCP OpenFlow::ofp_action_type

         Set the 802.1q priority.

      .. zeek:enum:: OpenFlow::OFPAT_STRIP_VLAN OpenFlow::ofp_action_type

         Strip the 802.1q header.

      .. zeek:enum:: OpenFlow::OFPAT_SET_DL_SRC OpenFlow::ofp_action_type

         Ethernet source address.

      .. zeek:enum:: OpenFlow::OFPAT_SET_DL_DST OpenFlow::ofp_action_type

         Ethernet destination address.

      .. zeek:enum:: OpenFlow::OFPAT_SET_NW_SRC OpenFlow::ofp_action_type

         IP source address.

      .. zeek:enum:: OpenFlow::OFPAT_SET_NW_DST OpenFlow::ofp_action_type

         IP destination address.

      .. zeek:enum:: OpenFlow::OFPAT_SET_NW_TOS OpenFlow::ofp_action_type

         IP ToS (DSCP field, 6 bits).

      .. zeek:enum:: OpenFlow::OFPAT_SET_TP_SRC OpenFlow::ofp_action_type

         TCP/UDP source port.

      .. zeek:enum:: OpenFlow::OFPAT_SET_TP_DST OpenFlow::ofp_action_type

         TCP/UDP destination port.

      .. zeek:enum:: OpenFlow::OFPAT_ENQUEUE OpenFlow::ofp_action_type

         Output to queue.

      .. zeek:enum:: OpenFlow::OFPAT_VENDOR OpenFlow::ofp_action_type

         Vendor specific.

   Openflow action_type definitions.
   
   The openflow action type defines
   what actions openflow can take
   to modify a packet

.. zeek:type:: OpenFlow::ofp_config_flags

   :Type: :zeek:type:`enum`

      .. zeek:enum:: OpenFlow::OFPC_FRAG_NORMAL OpenFlow::ofp_config_flags

         No special handling for fragments.

      .. zeek:enum:: OpenFlow::OFPC_FRAG_DROP OpenFlow::ofp_config_flags

         Drop fragments.

      .. zeek:enum:: OpenFlow::OFPC_FRAG_REASM OpenFlow::ofp_config_flags

         Reassemble (only if OFPC_IP_REASM set).

      .. zeek:enum:: OpenFlow::OFPC_FRAG_MASK OpenFlow::ofp_config_flags

   Openflow config flag definitions.
   
   TODO: describe

.. zeek:type:: OpenFlow::ofp_flow_mod_command

   :Type: :zeek:type:`enum`

      .. zeek:enum:: OpenFlow::OFPFC_ADD OpenFlow::ofp_flow_mod_command

         New flow.

      .. zeek:enum:: OpenFlow::OFPFC_MODIFY OpenFlow::ofp_flow_mod_command

         Modify all matching flows.

      .. zeek:enum:: OpenFlow::OFPFC_MODIFY_STRICT OpenFlow::ofp_flow_mod_command

         Modify entry strictly matching wildcards.

      .. zeek:enum:: OpenFlow::OFPFC_DELETE OpenFlow::ofp_flow_mod_command

         Delete all matching flows.

      .. zeek:enum:: OpenFlow::OFPFC_DELETE_STRICT OpenFlow::ofp_flow_mod_command

         Strictly matching wildcards and priority.

   Openflow flow_mod_command definitions.
   
   The openflow flow_mod_command describes
   of what kind an action is.


