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
                                                                from the Zeek openflow framework.
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
   :source-code: base/frameworks/openflow/consts.zeek 38 38

   :Type: :zeek:type:`count`
   :Default: ``32923``


.. zeek:id:: OpenFlow::ETH_APPLETALK_ARP
   :source-code: base/frameworks/openflow/consts.zeek 40 40

   :Type: :zeek:type:`count`
   :Default: ``33011``


.. zeek:id:: OpenFlow::ETH_ARP
   :source-code: base/frameworks/openflow/consts.zeek 32 32

   :Type: :zeek:type:`count`
   :Default: ``2054``


.. zeek:id:: OpenFlow::ETH_EAP_OVER_LAN
   :source-code: base/frameworks/openflow/consts.zeek 62 62

   :Type: :zeek:type:`count`
   :Default: ``34958``


.. zeek:id:: OpenFlow::ETH_ETHER_FLOW_CONTROL
   :source-code: base/frameworks/openflow/consts.zeek 50 50

   :Type: :zeek:type:`count`
   :Default: ``34824``


.. zeek:id:: OpenFlow::ETH_IPX
   :source-code: base/frameworks/openflow/consts.zeek 46 46

   :Type: :zeek:type:`count`
   :Default: ``33080``


.. zeek:id:: OpenFlow::ETH_IPX_OLD
   :source-code: base/frameworks/openflow/consts.zeek 44 44

   :Type: :zeek:type:`count`
   :Default: ``33079``


.. zeek:id:: OpenFlow::ETH_IPv4
   :source-code: base/frameworks/openflow/consts.zeek 30 30

   :Type: :zeek:type:`count`
   :Default: ``2048``


.. zeek:id:: OpenFlow::ETH_IPv6
   :source-code: base/frameworks/openflow/consts.zeek 48 48

   :Type: :zeek:type:`count`
   :Default: ``34525``


.. zeek:id:: OpenFlow::ETH_JUMBO_FRAMES
   :source-code: base/frameworks/openflow/consts.zeek 60 60

   :Type: :zeek:type:`count`
   :Default: ``34928``


.. zeek:id:: OpenFlow::ETH_MAC_SECURITY
   :source-code: base/frameworks/openflow/consts.zeek 66 66

   :Type: :zeek:type:`count`
   :Default: ``35045``


.. zeek:id:: OpenFlow::ETH_MPLS_MULTICAST
   :source-code: base/frameworks/openflow/consts.zeek 54 54

   :Type: :zeek:type:`count`
   :Default: ``34888``


.. zeek:id:: OpenFlow::ETH_MPLS_UNICAST
   :source-code: base/frameworks/openflow/consts.zeek 52 52

   :Type: :zeek:type:`count`
   :Default: ``34887``


.. zeek:id:: OpenFlow::ETH_PPPOE_DISCOVERY
   :source-code: base/frameworks/openflow/consts.zeek 56 56

   :Type: :zeek:type:`count`
   :Default: ``34915``


.. zeek:id:: OpenFlow::ETH_PPPOE_SESSION
   :source-code: base/frameworks/openflow/consts.zeek 58 58

   :Type: :zeek:type:`count`
   :Default: ``34916``


.. zeek:id:: OpenFlow::ETH_PROVIDER_BRIDING
   :source-code: base/frameworks/openflow/consts.zeek 64 64

   :Type: :zeek:type:`count`
   :Default: ``34984``


.. zeek:id:: OpenFlow::ETH_QINQ
   :source-code: base/frameworks/openflow/consts.zeek 68 68

   :Type: :zeek:type:`count`
   :Default: ``37120``


.. zeek:id:: OpenFlow::ETH_RARP
   :source-code: base/frameworks/openflow/consts.zeek 36 36

   :Type: :zeek:type:`count`
   :Default: ``32821``


.. zeek:id:: OpenFlow::ETH_VLAN
   :source-code: base/frameworks/openflow/consts.zeek 42 42

   :Type: :zeek:type:`count`
   :Default: ``33024``


.. zeek:id:: OpenFlow::ETH_WOL
   :source-code: base/frameworks/openflow/consts.zeek 34 34

   :Type: :zeek:type:`count`
   :Default: ``2114``


.. zeek:id:: OpenFlow::INVALID_COOKIE
   :source-code: base/frameworks/openflow/consts.zeek 126 126

   :Type: :zeek:type:`count`
   :Default: ``9223372036854775807``

   Return value for a cookie from a flow
   which is not added, modified or deleted
   from the Zeek openflow framework.

.. zeek:id:: OpenFlow::IP_CBT
   :source-code: base/frameworks/openflow/consts.zeek 89 89

   :Type: :zeek:type:`count`
   :Default: ``7``


.. zeek:id:: OpenFlow::IP_EGP
   :source-code: base/frameworks/openflow/consts.zeek 91 91

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: OpenFlow::IP_ETHERIP
   :source-code: base/frameworks/openflow/consts.zeek 112 112

   :Type: :zeek:type:`count`
   :Default: ``97``


.. zeek:id:: OpenFlow::IP_FC
   :source-code: base/frameworks/openflow/consts.zeek 118 118

   :Type: :zeek:type:`count`
   :Default: ``133``


.. zeek:id:: OpenFlow::IP_GGP
   :source-code: base/frameworks/openflow/consts.zeek 81 81

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: OpenFlow::IP_GRE
   :source-code: base/frameworks/openflow/consts.zeek 104 104

   :Type: :zeek:type:`count`
   :Default: ``47``


.. zeek:id:: OpenFlow::IP_HOPOPT
   :source-code: base/frameworks/openflow/consts.zeek 75 75

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: OpenFlow::IP_ICMP
   :source-code: base/frameworks/openflow/consts.zeek 77 77

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: OpenFlow::IP_IGMP
   :source-code: base/frameworks/openflow/consts.zeek 79 79

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: OpenFlow::IP_IGP
   :source-code: base/frameworks/openflow/consts.zeek 94 94

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: OpenFlow::IP_IPIP
   :source-code: base/frameworks/openflow/consts.zeek 83 83

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: OpenFlow::IP_IPv6
   :source-code: base/frameworks/openflow/consts.zeek 100 100

   :Type: :zeek:type:`count`
   :Default: ``41``


.. zeek:id:: OpenFlow::IP_ISIS
   :source-code: base/frameworks/openflow/consts.zeek 116 116

   :Type: :zeek:type:`count`
   :Default: ``124``


.. zeek:id:: OpenFlow::IP_L2TP
   :source-code: base/frameworks/openflow/consts.zeek 114 114

   :Type: :zeek:type:`count`
   :Default: ``115``


.. zeek:id:: OpenFlow::IP_MPLS
   :source-code: base/frameworks/openflow/consts.zeek 120 120

   :Type: :zeek:type:`count`
   :Default: ``137``


.. zeek:id:: OpenFlow::IP_MTP
   :source-code: base/frameworks/openflow/consts.zeek 108 108

   :Type: :zeek:type:`count`
   :Default: ``92``


.. zeek:id:: OpenFlow::IP_OSPF
   :source-code: base/frameworks/openflow/consts.zeek 106 106

   :Type: :zeek:type:`count`
   :Default: ``89``


.. zeek:id:: OpenFlow::IP_RDP
   :source-code: base/frameworks/openflow/consts.zeek 98 98

   :Type: :zeek:type:`count`
   :Default: ``27``


.. zeek:id:: OpenFlow::IP_RSVP
   :source-code: base/frameworks/openflow/consts.zeek 102 102

   :Type: :zeek:type:`count`
   :Default: ``46``


.. zeek:id:: OpenFlow::IP_ST
   :source-code: base/frameworks/openflow/consts.zeek 85 85

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: OpenFlow::IP_TCP
   :source-code: base/frameworks/openflow/consts.zeek 87 87

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: OpenFlow::IP_UDP
   :source-code: base/frameworks/openflow/consts.zeek 96 96

   :Type: :zeek:type:`count`
   :Default: ``17``


.. zeek:id:: OpenFlow::OFPFF_CHECK_OVERLAP
   :source-code: base/frameworks/openflow/consts.zeek 155 155

   :Type: :zeek:type:`count`
   :Default: ``2``

   Check for overlapping entries first.

.. zeek:id:: OpenFlow::OFPFF_EMERG
   :source-code: base/frameworks/openflow/consts.zeek 159 159

   :Type: :zeek:type:`count`
   :Default: ``4``

   Remark this is for emergency.
   Flows added with this are only used
   when the controller is disconnected.

.. zeek:id:: OpenFlow::OFPFF_SEND_FLOW_REM
   :source-code: base/frameworks/openflow/consts.zeek 153 153

   :Type: :zeek:type:`count`
   :Default: ``1``

   Send flow removed message when flow
   expires or is deleted.

.. zeek:id:: OpenFlow::OFPP_ALL
   :source-code: base/frameworks/openflow/consts.zeek 142 142

   :Type: :zeek:type:`count`
   :Default: ``4294967292``

   All physical ports except input port.

.. zeek:id:: OpenFlow::OFPP_ANY
   :source-code: base/frameworks/openflow/consts.zeek 148 148

   :Type: :zeek:type:`count`
   :Default: ``4294967295``

   Wildcard port used only for flow mod (delete) and flow stats requests.

.. zeek:id:: OpenFlow::OFPP_CONTROLLER
   :source-code: base/frameworks/openflow/consts.zeek 144 144

   :Type: :zeek:type:`count`
   :Default: ``4294967293``

   Send to controller.

.. zeek:id:: OpenFlow::OFPP_FLOOD
   :source-code: base/frameworks/openflow/consts.zeek 140 140

   :Type: :zeek:type:`count`
   :Default: ``4294967291``

   All physical ports except input port and
   those disabled by STP.

.. zeek:id:: OpenFlow::OFPP_IN_PORT
   :source-code: base/frameworks/openflow/consts.zeek 131 131

   :Type: :zeek:type:`count`
   :Default: ``4294967288``

   Send the packet out the input port. This
   virtual port must be explicitly used in
   order to send back out of the input port.

.. zeek:id:: OpenFlow::OFPP_LOCAL
   :source-code: base/frameworks/openflow/consts.zeek 146 146

   :Type: :zeek:type:`count`
   :Default: ``4294967294``

   Local openflow "port".

.. zeek:id:: OpenFlow::OFPP_NORMAL
   :source-code: base/frameworks/openflow/consts.zeek 137 137

   :Type: :zeek:type:`count`
   :Default: ``4294967290``

   Process with normal L2/L3 switching.

.. zeek:id:: OpenFlow::OFPP_TABLE
   :source-code: base/frameworks/openflow/consts.zeek 135 135

   :Type: :zeek:type:`count`
   :Default: ``4294967289``

   Perform actions in flow table.
   NB: This can only be the destination port
   for packet-out messages.

.. zeek:id:: OpenFlow::OFPTT_ALL
   :source-code: base/frameworks/openflow/consts.zeek 163 163

   :Type: :zeek:type:`count`
   :Default: ``255``


.. zeek:id:: OpenFlow::OFP_NO_BUFFER
   :source-code: base/frameworks/openflow/consts.zeek 150 150

   :Type: :zeek:type:`count`
   :Default: ``4294967295``


Types
#####
.. zeek:type:: OpenFlow::ofp_action_type
   :source-code: base/frameworks/openflow/consts.zeek 170 198

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
   :source-code: base/frameworks/openflow/consts.zeek 219 228

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
   :source-code: base/frameworks/openflow/consts.zeek 203 215

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


