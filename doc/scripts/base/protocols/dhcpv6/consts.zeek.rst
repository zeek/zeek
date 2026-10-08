:tocdepth: 3

base/protocols/dhcpv6/consts.zeek
=================================
.. zeek:namespace:: DHCPv6


:Namespace: DHCPv6

Summary
~~~~~~~
Constants
#########
================================================================================================== ===================================
:zeek:id:`DHCPv6::duid_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`    DUID types
:zeek:id:`DHCPv6::message_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`
:zeek:id:`DHCPv6::option_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  Option types mapped to their names.
:zeek:id:`DHCPv6::status_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  Status codes
================================================================================================== ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: DHCPv6::duid_types
   :source-code: base/protocols/dhcpv6/consts.zeek 19 19

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [4] = "UUID",
            [2] = "EN",
            [3] = "LL",
            [1] = "LLT"
         }


   DUID types

.. zeek:id:: DHCPv6::message_types
   :source-code: base/protocols/dhcpv6/consts.zeek 4 4

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "ADVERTISE",
            [11] = "INFORMATION_REQUEST",
            [5] = "RENEW",
            [7] = "REPLY",
            [6] = "REBIND",
            [10] = "RECONFIGURE",
            [4] = "CONFIRM",
            [8] = "RELEASE",
            [3] = "REQUEST",
            [9] = "DECLINE",
            [1] = "SOLICIT"
         }



.. zeek:id:: DHCPv6::option_types
   :source-code: base/protocols/dhcpv6/consts.zeek 56 56

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [96] = "S46_CONT_LW",
            [73] = "MIP6_HAF",
            [39] = "CLIENT_FQDN",
            [46] = "CLT_TIME",
            [28] = "NISP_SERVERS",
            [9] = "RELAY_MSG",
            [68] = "VSS",
            [107] = "ANI_AP_NAME",
            [53] = "RELAY_ID",
            [71] = "MIP6_HNP",
            [127] = "F_PROTOCOL_VERSION",
            [52] = "CAPWAP_AC_V6",
            [41] = "NEW_POSIX_TIMEZONE",
            [17] = "VENDOR_OPTS",
            [105] = "ANI_ATT",
            [119] = "F_DNS_FLAGS",
            [81] = "RADIUS",
            [88] = "DHCP4_O_DHCP6_SERVER",
            [111] = "S46_PRIORITY",
            [29] = "NIS_DOMAIN_NAME",
            [115] = "F_CONNECT_FLAGS",
            [133] = "F_START_TIME_OF_STATE",
            [95] = "S46_CONT_MAPT",
            [54] = "IPv6_Address-MoS",
            [90] = "S46_BR",
            [146] = "FORWARD_DIST_MANAGER",
            [86] = "V6_PCP_SERVER",
            [1] = "CLIENTID",
            [116] = "F_DNS_REMOVAL_INFO",
            [35] = "Unassigned",
            [102] = "LQ_END_TIME",
            [135] = "RELAY_PORT",
            [3] = "IA_NA",
            [114] = "F_BINDING_STATUS",
            [140] = "SLAP_QUAD",
            [44] = "LQ_QUERY",
            [129] = "F_RECONFIGURE_DATA",
            [34] = "BCMCS_SERVER_A",
            [45] = "CLIENT_DATA",
            [14] = "RAPID_COMMIT",
            [31] = "SNTP_SERVERS",
            [82] = "SOL_MAX_RT",
            [56] = "NTP_SERVER",
            [7] = "PREFERENCE",
            [66] = "RSOO",
            [26] = "IAPREFIX",
            [128] = "F_KEEPALIVE_TIME",
            [47] = "LQ_RELAY_DATA",
            [70] = "MIP6_UDINF",
            [93] = "S46_PORTPARAMS",
            [147] = "REVERSE_DIST_MANAGER",
            [2] = "SERVERID",
            [132] = "F_SERVER_STATE",
            [72] = "MIP6_HAA",
            [24] = "DOMAIN_LIST",
            [69] = "MIP6_IDINF",
            [99] = "4RD_NON_MAP_RULE",
            [109] = "ANI_OPERATOR_ID",
            [103] = "DHCP_Captive_Portal",
            [126] = "F_PARTNER_RAW_CLT_TIME",
            [104] = "MPL_PARAMETERS",
            [61] = "CLIENT_ARCH_TYPE",
            [60] = "OPT_BOOTFILE_PARAM",
            [51] = "V6_LOST",
            [37] = "REMOTE_ID",
            [18] = "INTERFACE_ID",
            [0] = "Reserved",
            [110] = "ANI_OPERATOR_REALM",
            [137] = "S46_BIND_IPV6_PREFIX",
            [94] = "S46_CONT_MAPE",
            [19] = "RECONF_MSG",
            [20] = "RECONF_ACCEPT",
            [33] = "BCMCS_SERVER_D",
            [75] = "KRB_PRINCIPAL_NAME",
            [67] = "PD_EXCLUDE",
            [15] = "USER_CLASS",
            [30] = "NISP_DOMAIN_NAME",
            [77] = "KRB_DEFAULT_REALM_NAME",
            [64] = "AFTR_NAME",
            [106] = "ANI_NETWORK_NAME",
            [91] = "S46_DMR",
            [97] = "4RD",
            [55] = "IPv6_FQDN-MoS",
            [21] = "SIP_SERVER_D",
            [4] = "IA_TA",
            [12] = "UNICAST",
            [124] = "F_PARTNER_LIFETIME_SENT",
            [130] = "F_RELATIONSHIP_NAME",
            [58] = "SIP_UA_CS_LIST",
            [134] = "F_STATE_EXPIRATION_TIME",
            [80] = "LINK_ADDRESS",
            [76] = "KRB_REALM_NAME",
            [25] = "IA_PD",
            [142] = "V6_DOTS_ADDRESS",
            [16] = "VENDOR_CLASS",
            [59] = "OPT_BOOTFILE_URL",
            [38] = "SUBSCRIBER_ID",
            [63] = "GEOLOCATION",
            [42] = "NEW_TZDB_TIMEZONE",
            [57] = "V6_ACCESS_DOMAIN",
            [78] = "KRB_KDC",
            [98] = "4RD_MAP_RULE",
            [11] = "AUTH",
            [113] = "V6_PREFIX64",
            [108] = "ANI_AP_BSSID",
            [22] = "SIP_SERVER_A",
            [43] = "ERO",
            [143] = "IPv6_Address-ANDSF",
            [136] = "V6_SZTP_REDIRECT",
            [144] = "V6_DNR",
            [40] = "PANA_AGENT",
            [36] = "GEOCONF_CIVIC",
            [6] = "ORO",
            [125] = "F_PARTNER_DOWN_TIME",
            [141] = "V6_DOTS_RI",
            [8] = "ELAPSED_TIME",
            [23] = "DNS_SERVERS",
            [27] = "NIS_SERVERS",
            [145] = "REGISTERED_DOMAIN",
            [83] = "INF_MAX_RT",
            [122] = "F_MCLT",
            [92] = "S46_V4V6BIND",
            [10] = "Unassigned",
            [65] = "ERP_LOCAL_DOMAIN_NAME",
            [13] = "STATUS_CODE",
            [32] = "INFORMATION_REFRESH_TIME",
            [74] = "RDNSS_SELECTION",
            [62] = "NII",
            [148] = "ADDR_REG_ENABLE",
            [101] = "LQ_START_TIME",
            [118] = "F_DNS_ZONE_NAME",
            [138] = "IA_LL",
            [89] = "S46_RULE",
            [139] = "LLADDR",
            [120] = "F_EXPIRATION_TIME",
            [50] = "MIP6_VDINF",
            [79] = "CLIENT_LINKLAYER_ADDR",
            [121] = "F_MAX_UNACKED_BNDUPD",
            [48] = "LQ_CLIENT_LINK",
            [85] = "ADDRSEL_TABLE",
            [49] = "MIP6_HNIDF",
            [5] = "IAADDR",
            [112] = "MUD_URL_V6",
            [100] = "LQ_BASE_TIME",
            [117] = "F_DNS_HOST_NAME",
            [123] = "F_PARTNER_LIFETIME",
            [131] = "F_SERVER_FLAGS",
            [87] = "DHCPV4_MSG",
            [84] = "ADDRSEL"
         }


   Option types mapped to their names.

.. zeek:id:: DHCPv6::status_codes
   :source-code: base/protocols/dhcpv6/consts.zeek 28 28

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "OutdatedBindingInformation",
            [2] = "NoAddrsAvail",
            [20] = "ServerShuttingDown",
            [14] = "NotSupported",
            [15] = "TLSConnectionRefused",
            [6] = "NoPrefixAvail",
            [16] = "AddressInUse",
            [8] = "MalformedQuery",
            [9] = "NotConfigured",
            [1] = "UnspecFail",
            [11] = "QueryTerminated",
            [7] = "UnknownQueryType",
            [5] = "UseMulticast",
            [10] = "NotAllowed",
            [21] = "DNSUpdateNotSupported",
            [4] = "NotOnLink",
            [22] = "ExcessiveTimeSkew",
            [13] = "CatchUpComplete",
            [12] = "DataMissing",
            [18] = "MissingBindingInformation",
            [17] = "ConfigurationConflict",
            [3] = "NoBinding",
            [0] = "Success"
         }


   Status codes


