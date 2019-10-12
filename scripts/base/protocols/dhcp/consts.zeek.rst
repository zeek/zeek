:tocdepth: 3

base/protocols/dhcp/consts.zeek
===============================
.. zeek:namespace:: DHCP

Types, errors, and fields for analyzing DHCP data.  A helper file
for DHCP analysis scripts.

:Namespace: DHCP

Summary
~~~~~~~
Constants
#########
================================================================================================ ===================================
:zeek:id:`DHCP::message_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Types of DHCP messages.
:zeek:id:`DHCP::option_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  Option types mapped to their names.
================================================================================================ ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: DHCP::message_types

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "OFFER",
            [9] = "FORCERENEW",
            [17] = "LEASEQUERYSTATUS",
            [6] = "NAK",
            [11] = "LEASEUNASSIGNED",
            [14] = "BULKLEASEQUERY",
            [4] = "DECLINE",
            [1] = "DISCOVER",
            [8] = "INFORM",
            [7] = "RELEASE",
            [15] = "LEASEQUERYDONE",
            [5] = "ACK",
            [10] = "LEASEQUERY",
            [3] = "REQUEST",
            [12] = "LEASEUNKNOWN",
            [13] = "LEASEACTIVE",
            [18] = "TLS",
            [16] = "ACTIVELEASEQUERY"
         }


   Types of DHCP messages. See :rfc:`1533`, :rfc:`3203`,
   :rfc:`4388`, :rfc:`6926`, and :rfc:`7724`.

.. zeek:id:: DHCP::option_types

   :Type: :zeek:type:`table` [:zeek:type:`int`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [124] = "V-I Vendor Class",
            [7] = "Log Server",
            [22] = "Max DG Assembly",
            [211] = "Reboot Time",
            [213] = "OPTION_V4_ACCESS_DOMAIN",
            [51] = "Address Time",
            [3] = "Router",
            [75] = "StreetTalk-Server",
            [156] = "dhcp-state",
            [4] = "Time Server",
            [48] = "X Window Font",
            [26] = "MTU Interface",
            [10] = "Impress Server",
            [11] = "RLP Server",
            [90] = "Authentication",
            [125] = "V-I Vendor-Specific Information",
            [212] = "OPTION_6RD",
            [123] = "GeoConf Option",
            [175] = "Etherboot (Tentatively Assigned - 2005-06-23)",
            [45] = "NETBIOS Dist Srv",
            [39] = "Keepalive Data",
            [62] = "NetWare/IP Domain",
            [132] = "IEEE 802.1Q VLAN ID",
            [35] = "ARP Timeout",
            [93] = "Client System",
            [129] = "PXE - undefined (vendor specific)",
            [34] = "Trailers",
            [97] = "UUID/GUID",
            [153] = "start-time-of-state",
            [1] = "Subnet Mask",
            [30] = "Mask Supplier",
            [65] = "NIS-Server-Addr",
            [42] = "NTP Servers",
            [142] = "OPTION-IPv4_Address-ANDSF",
            [76] = "STDA-Server",
            [137] = "OPTION_V4_LOST",
            [209] = "Configuration File",
            [56] = "DHCP Message",
            [46] = "NETBIOS Node Type",
            [100] = "PCode",
            [146] = "RDNSS Selection",
            [220] = "Subnet Allocation Option",
            [151] = "status-code",
            [67] = "Bootfile-Name",
            [81] = "Client FQDN",
            [144] = "GeoLoc",
            [70] = "POP3-Server",
            [2] = "Time Offset",
            [15] = "Domain Name",
            [210] = "Path Prefix",
            [119] = "Domain Search",
            [83] = "iSNS",
            [36] = "Ethernet",
            [79] = "Service Scope",
            [32] = "Router Request",
            [23] = "Default IP TTL",
            [221] = "Virtual Subnet Selection (VSS) Option",
            [120] = "SIP Servers DHCP Option",
            [40] = "NIS Domain",
            [16] = "Swap Server",
            [80] = "Rapid Commit",
            [159] = "OPTION_V4_PORTPARAMS",
            [94] = "Client NDI",
            [8] = "Quotes Server",
            [131] = "PXE - undefined (vendor specific)",
            [78] = "Directory Agent",
            [134] = "Diffserv Code Point (DSCP) for VoIP signalling and media streams",
            [141] = "SIP UA Configuration Service Domains",
            [69] = "SMTP-Server",
            [59] = "Rebinding Time",
            [154] = "query-start-time",
            [55] = "Parameter List",
            [155] = "query-end-time",
            [77] = "User-Class",
            [49] = "X Window Manager",
            [50] = "Address Request",
            [113] = "Netinfo Tag",
            [9] = "LPR Server",
            [0] = "Pad",
            [66] = "Server-Name",
            [138] = "OPTION_CAPWAP_AC_V4",
            [139] = "OPTION-IPv4_Address-MoS",
            [20] = "SrcRte On/Off",
            [18] = "Extension File",
            [37] = "Default TCP TTL",
            [89] = "BCMCS Controller IPv4 address option",
            [98] = "User-Auth",
            [122] = "CCC",
            [158] = "OPTION_V4_PCP_SERVER",
            [255] = "End",
            [63] = "NetWare/IP Option",
            [53] = "DHCP Msg Type",
            [128] = "PXE - undefined (vendor specific)",
            [60] = "Class Id",
            [136] = "OPTION_PANA_AGENT",
            [72] = "WWW-Server",
            [116] = "Auto-Config",
            [130] = "PXE - undefined (vendor specific)",
            [85] = "NDS Servers",
            [73] = "Finger-Server",
            [88] = "BCMCS Controller Domain Name list",
            [208] = "PXELINUX Magic",
            [19] = "Forward On/Off",
            [112] = "Netinfo Address",
            [54] = "DHCP Server Id",
            [68] = "Home-Agent-Addrs",
            [5] = "Name Server",
            [114] = "URL",
            [44] = "NETBIOS Name Srv",
            [13] = "Boot File Size",
            [47] = "NETBIOS Scope",
            [58] = "Renewal Time",
            [29] = "Mask Discovery",
            [12] = "Hostname",
            [17] = "Root Path",
            [135] = "HTTP Proxy for phone-specific applications",
            [61] = "Client Id",
            [99] = "GEOCONF_CIVIC",
            [25] = "MTU Plateau",
            [121] = "Classless Static Route Option",
            [71] = "NNTP-Server",
            [117] = "Name Service Search",
            [118] = "Subnet Selection Option",
            [176] = "IP Telephone (Tentatively Assigned - 2005-06-23)",
            [38] = "Keepalive Time",
            [57] = "DHCP Max Msg Size",
            [252] = "auto-proxy-config",
            [52] = "Overload",
            [150] = "TFTP server address",
            [140] = "OPTION-IPv4_FQDN-MoS",
            [43] = "Vendor Specific",
            [41] = "NIS Servers",
            [101] = "TCode",
            [87] = "NDS Context",
            [74] = "IRC-Server",
            [6] = "Domain Server",
            [177] = "PacketCable and CableHome (replaced by 122)",
            [91] = "client-last-transaction-time option",
            [82] = "Relay Agent Information",
            [161] = "OPTION_MUD_URL_V4 (TEMPORARY - registered 2016-11-17)",
            [64] = "NIS-Domain-Name",
            [95] = "LDAP",
            [133] = "IEEE 802.1D/p Layer 2 Priority",
            [14] = "Merit Dump File",
            [27] = "MTU Subnet",
            [31] = "Router Discovery",
            [24] = "MTU Timeout",
            [152] = "base-time",
            [160] = "DHCP Captive-Portal",
            [145] = "FORCERENEW_NONCE_CAPABLE",
            [28] = "Broadcast Address",
            [33] = "Static Route",
            [92] = "associated-ip option",
            [21] = "Policy Filter",
            [157] = "data-source",
            [86] = "NDS Tree Name"
         }


   Option types mapped to their names.


