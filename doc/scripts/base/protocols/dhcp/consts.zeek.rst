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
   :source-code: base/protocols/dhcp/consts.zeek 9 9

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "OFFER",
            [14] = "BULKLEASEQUERY",
            [6] = "NAK",
            [15] = "LEASEQUERYDONE",
            [16] = "ACTIVELEASEQUERY",
            [8] = "INFORM",
            [9] = "FORCERENEW",
            [1] = "DISCOVER",
            [11] = "LEASEUNASSIGNED",
            [7] = "RELEASE",
            [5] = "ACK",
            [10] = "LEASEQUERY",
            [4] = "DECLINE",
            [12] = "LEASEUNKNOWN",
            [13] = "LEASEACTIVE",
            [18] = "TLS",
            [3] = "REQUEST",
            [17] = "LEASEQUERYSTATUS"
         }


   Types of DHCP messages. See :rfc:`1533`, :rfc:`3203`,
   :rfc:`4388`, :rfc:`6926`, and :rfc:`7724`.

.. zeek:id:: DHCP::option_types
   :source-code: base/protocols/dhcp/consts.zeek 31 31

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [39] = "Keepalive Data",
            [73] = "Finger-Server",
            [46] = "NETBIOS Node Type",
            [28] = "Broadcast Address",
            [212] = "OPTION_6RD",
            [9] = "LPR Server",
            [68] = "Home-Agent-Addrs",
            [53] = "DHCP Msg Type",
            [71] = "NNTP-Server",
            [52] = "Overload",
            [41] = "NIS Servers",
            [17] = "Root Path",
            [119] = "Domain Search",
            [81] = "Client FQDN",
            [88] = "BCMCS Controller Domain Name list",
            [29] = "Mask Discovery",
            [133] = "IEEE 802.1D/p Layer 2 Priority",
            [176] = "IP Telephone (Tentatively Assigned - 2005-06-23)",
            [213] = "OPTION_V4_ACCESS_DOMAIN",
            [54] = "DHCP Server Id",
            [95] = "LDAP",
            [90] = "Authentication",
            [252] = "auto-proxy-config",
            [146] = "RDNSS Selection",
            [86] = "NDS Tree Name",
            [1] = "Subnet Mask",
            [116] = "Auto-Config",
            [158] = "OPTION_V4_PCP_SERVER",
            [35] = "ARP Timeout",
            [135] = "HTTP Proxy for phone-specific applications",
            [3] = "Router",
            [114] = "URL",
            [140] = "OPTION-IPv4_FQDN-MoS",
            [44] = "NETBIOS Name Srv",
            [129] = "PXE - undefined (vendor specific)",
            [34] = "Trailers",
            [45] = "NETBIOS Dist Srv",
            [14] = "Merit Dump File",
            [31] = "Router Discovery",
            [82] = "Relay Agent Information",
            [56] = "DHCP Message",
            [7] = "Log Server",
            [66] = "Server-Name",
            [26] = "MTU Interface",
            [128] = "PXE - undefined (vendor specific)",
            [175] = "Etherboot (Tentatively Assigned - 2005-06-23)",
            [47] = "NETBIOS Scope",
            [70] = "POP3-Server",
            [93] = "Client System",
            [2] = "Time Offset",
            [132] = "IEEE 802.1Q VLAN ID",
            [72] = "WWW-Server",
            [24] = "MTU Timeout",
            [69] = "SMTP-Server",
            [99] = "GEOCONF_CIVIC",
            [161] = "OPTION_MUD_URL_V4 (TEMPORARY - registered 2016-11-17)",
            [61] = "Client Id",
            [60] = "Class Id",
            [51] = "Address Time",
            [37] = "Default TCP TTL",
            [18] = "Extension File",
            [157] = "data-source",
            [0] = "Pad",
            [220] = "Subnet Allocation Option",
            [137] = "OPTION_V4_LOST",
            [94] = "Client NDI",
            [19] = "Forward On/Off",
            [20] = "SrcRte On/Off",
            [33] = "Static Route",
            [75] = "StreetTalk-Server",
            [67] = "Bootfile-Name",
            [30] = "Mask Supplier",
            [15] = "Domain Name",
            [77] = "User-Class",
            [64] = "NIS-Domain-Name",
            [211] = "Reboot Time",
            [91] = "client-last-transaction-time option",
            [156] = "dhcp-state",
            [177] = "PacketCable and CableHome (replaced by 122)",
            [97] = "UUID/GUID",
            [55] = "Parameter List",
            [21] = "Policy Filter",
            [221] = "Virtual Subnet Selection (VSS) Option",
            [4] = "Time Server",
            [124] = "V-I Vendor Class",
            [130] = "PXE - undefined (vendor specific)",
            [12] = "Hostname",
            [155] = "query-end-time",
            [58] = "Renewal Time",
            [134] = "Diffserv Code Point (DSCP) for VoIP signalling and media streams",
            [80] = "Rapid Commit",
            [150] = "TFTP server address",
            [76] = "STDA-Server",
            [25] = "MTU Plateau",
            [142] = "OPTION-IPv4_Address-ANDSF",
            [16] = "Swap Server",
            [255] = "End",
            [59] = "Rebinding Time",
            [210] = "Path Prefix",
            [38] = "Keepalive Time",
            [154] = "query-start-time",
            [63] = "NetWare/IP Option",
            [42] = "NTP Servers",
            [57] = "DHCP Max Msg Size",
            [78] = "Directory Agent",
            [98] = "User-Auth",
            [113] = "Netinfo Tag",
            [11] = "RLP Server",
            [22] = "Max DG Assembly",
            [43] = "Vendor Specific",
            [136] = "OPTION_PANA_AGENT",
            [144] = "GeoLoc",
            [40] = "NIS Domain",
            [151] = "status-code",
            [208] = "PXELINUX Magic",
            [36] = "Ethernet",
            [6] = "Domain Server",
            [141] = "SIP UA Configuration Service Domains",
            [125] = "V-I Vendor-Specific Information",
            [8] = "Quotes Server",
            [23] = "Default IP TTL",
            [27] = "MTU Subnet",
            [145] = "FORCERENEW_NONCE_CAPABLE",
            [83] = "iSNS",
            [122] = "CCC",
            [159] = "OPTION_V4_PORTPARAMS",
            [92] = "associated-ip option",
            [10] = "Impress Server",
            [65] = "NIS-Server-Addr",
            [13] = "Boot File Size",
            [32] = "Router Request",
            [74] = "IRC-Server",
            [62] = "NetWare/IP Domain",
            [101] = "TCode",
            [89] = "BCMCS Controller IPv4 address option",
            [118] = "Subnet Selection Option",
            [138] = "OPTION_CAPWAP_AC_V4",
            [160] = "DHCP Captive-Portal",
            [139] = "OPTION-IPv4_Address-MoS",
            [120] = "SIP Servers DHCP Option",
            [152] = "base-time",
            [50] = "Address Request",
            [79] = "Service Scope",
            [121] = "Classless Static Route Option",
            [48] = "X Window Font",
            [85] = "NDS Servers",
            [49] = "X Window Manager",
            [209] = "Configuration File",
            [112] = "Netinfo Address",
            [5] = "Name Server",
            [100] = "PCode",
            [117] = "Name Service Search",
            [123] = "GeoConf Option",
            [131] = "PXE - undefined (vendor specific)",
            [87] = "NDS Context",
            [153] = "start-time-of-state"
         }


   Option types mapped to their names.


