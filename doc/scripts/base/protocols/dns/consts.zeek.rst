:tocdepth: 3

base/protocols/dns/consts.zeek
==============================
.. zeek:namespace:: DNS

Types, errors, and fields for analyzing DNS data.  A helper file
for DNS analysis scripts.

:Namespace: DNS

Summary
~~~~~~~
Constants
#########
================================================================================================= ===============================================================================
:zeek:id:`DNS::ANY`: :zeek:type:`count`                                                           A QTYPE value describing a request for all records.
:zeek:id:`DNS::DNS_OP_DSO`: :zeek:type:`count`                                                    
:zeek:id:`DNS::DNS_OP_DYNAMIC_UPDATE`: :zeek:type:`count`                                         
:zeek:id:`DNS::DNS_OP_IQUERY`: :zeek:type:`count`                                                 
:zeek:id:`DNS::DNS_OP_NOTIFY`: :zeek:type:`count`                                                 
:zeek:id:`DNS::DNS_OP_QUERY`: :zeek:type:`count`                                                  
:zeek:id:`DNS::DNS_OP_SERVER_STATUS`: :zeek:type:`count`                                          
:zeek:id:`DNS::EDNS`: :zeek:type:`count`                                                          An OPT RR TYPE value described by EDNS.
:zeek:id:`DNS::NONE`: :zeek:type:`count`                                                          A class representing no classes, used by dynamic update.
:zeek:id:`DNS::PTR`: :zeek:type:`count`                                                           RR TYPE value for a domain name pointer.
:zeek:id:`DNS::algorithms`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      Possible values of the algorithms used in DNSKEY, DS and RRSIG records
:zeek:id:`DNS::base_errors`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`     Errors used for non-TSIG/EDNS types.
:zeek:id:`DNS::classes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         Possible values of the CLASS field in resource records or QCLASS
                                                                                                  field in query messages.
:zeek:id:`DNS::digests`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         Possible digest types used in DNSSEC.
:zeek:id:`DNS::edns_zfield`: :zeek:type:`table` :zeek:attr:`&default` = ``"?"``                   This deciphers EDNS Z field values.
:zeek:id:`DNS::netbios_opcodes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Mapping of DNS operation type codes to human readable string representation for
                                                                                                  NetBIOS Name Service (NBNS) queries.
:zeek:id:`DNS::opcodes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         Mapping of DNS operation type codes to human readable string representation.
:zeek:id:`DNS::query_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`     Mapping of DNS query type codes to human readable string
                                                                                                  representation.
:zeek:id:`DNS::svcparam_keys`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`   SVCB/HTTPS SvcParam keys as defined in :rfc:`9460#name-initial-contents`.
================================================================================================= ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: DNS::ANY
   :source-code: base/protocols/dns/consts.zeek 10 10

   :Type: :zeek:type:`count`
   :Default: ``255``

   A QTYPE value describing a request for all records.

.. zeek:id:: DNS::DNS_OP_DSO
   :source-code: base/protocols/dns/consts.zeek 203 203

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: DNS::DNS_OP_DYNAMIC_UPDATE
   :source-code: base/protocols/dns/consts.zeek 202 202

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: DNS::DNS_OP_IQUERY
   :source-code: base/protocols/dns/consts.zeek 199 199

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: DNS::DNS_OP_NOTIFY
   :source-code: base/protocols/dns/consts.zeek 201 201

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: DNS::DNS_OP_QUERY
   :source-code: base/protocols/dns/consts.zeek 198 198

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: DNS::DNS_OP_SERVER_STATUS
   :source-code: base/protocols/dns/consts.zeek 200 200

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: DNS::EDNS
   :source-code: base/protocols/dns/consts.zeek 8 8

   :Type: :zeek:type:`count`
   :Default: ``41``

   An OPT RR TYPE value described by EDNS.

.. zeek:id:: DNS::NONE
   :source-code: base/protocols/dns/consts.zeek 9 9

   :Type: :zeek:type:`count`
   :Default: ``254``

   A class representing no classes, used by dynamic update.

.. zeek:id:: DNS::PTR
   :source-code: base/protocols/dns/consts.zeek 7 7

   :Type: :zeek:type:`count`
   :Default: ``12``

   RR TYPE value for a domain name pointer.

.. zeek:id:: DNS::algorithms
   :source-code: base/protocols/dns/consts.zeek 155 155

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [254] = "PrivateOID",
            [2] = "Diffie_Hellman",
            [15] = "Ed25519",
            [6] = "DSA_NSEC3_SHA1",
            [14] = "ECDSA_curveP384withSHA384",
            [16] = "Ed448",
            [255] = "reserved255",
            [8] = "RSA_SHA256",
            [252] = "Indirect",
            [253] = "PrivateDNS",
            [1] = "RSA_MD5",
            [5] = "RSA_SHA1",
            [7] = "RSA_SHA1_NSEC3_SHA1",
            [10] = "RSA_SHA512",
            [4] = "Elliptic_Curve",
            [12] = "GOST_R_34_10_2001",
            [13] = "ECDSA_curveP256withSHA256",
            [3] = "DSA_SHA1",
            [0] = "reserved0"
         }


   Possible values of the algorithms used in DNSKEY, DS and RRSIG records

.. zeek:id:: DNS::base_errors
   :source-code: base/protocols/dns/consts.zeek 108 108

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "BADMODE",
            [3842] = "BADSIG",
            [20] = "BADNAME",
            [2] = "SERVFAIL",
            [14] = "unassigned-14",
            [15] = "unassigned-15",
            [6] = "YXDOMAIN",
            [16] = "BADVERS",
            [8] = "NXRRSet",
            [23] = "BADCOOKIE",
            [9] = "NOTAUTH",
            [1] = "FORMERR",
            [11] = "unassigned-11",
            [7] = "YXRRSET",
            [5] = "REFUSED",
            [10] = "NOTZONE",
            [21] = "BADALG",
            [4] = "NOTIMP",
            [22] = "BADTRUNC",
            [13] = "unassigned-13",
            [12] = "unassigned-12",
            [18] = "BADTIME",
            [17] = "BADKEY",
            [3] = "NXDOMAIN",
            [0] = "NOERROR"
         }


   Errors used for non-TSIG/EDNS types.

.. zeek:id:: DNS::classes
   :source-code: base/protocols/dns/consts.zeek 145 145

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [254] = "C_NONE",
            [2] = "C_CSNET",
            [3] = "C_CHAOS",
            [255] = "C_ANY",
            [4] = "C_HESIOD",
            [1] = "C_INTERNET"
         }


   Possible values of the CLASS field in resource records or QCLASS
   field in query messages.

.. zeek:id:: DNS::digests
   :source-code: base/protocols/dns/consts.zeek 178 178

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "reserved0",
            [2] = "SHA256",
            [4] = "SHA384",
            [1] = "SHA1",
            [3] = "GOST_R_34_11_94"
         }


   Possible digest types used in DNSSEC.

.. zeek:id:: DNS::edns_zfield
   :source-code: base/protocols/dns/consts.zeek 138 138

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = ``"?"``
   :Default:

      ::

         {
            [0] = "NOVALUE",
            [32768] = "DNS_SEC_OK"
         }


   This deciphers EDNS Z field values.

.. zeek:id:: DNS::netbios_opcodes
   :source-code: base/protocols/dns/consts.zeek 218 218

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "netbios-query",
            [6] = "netbios-release",
            [8] = "netbios-refresh",
            [7] = "netbios-wack",
            [5] = "netbios-registration"
         }


   Mapping of DNS operation type codes to human readable string representation for
   NetBIOS Name Service (NBNS) queries. These codes are defined in
   https://datatracker.ietf.org/doc/html/rfc1002#section-4.2.1.1

.. zeek:id:: DNS::opcodes
   :source-code: base/protocols/dns/consts.zeek 206 206

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "query",
            [6] = "dso",
            [4] = "notify",
            [2] = "server-status",
            [1] = "iquery",
            [5] = "dynamic-update"
         }


   Mapping of DNS operation type codes to human readable string representation.

.. zeek:id:: DNS::query_types
   :source-code: base/protocols/dns/consts.zeek 14 14

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "X25",
            [20] = "ISDN",
            [33] = "SRV",
            [39] = "DNAME",
            [30] = "NXT",
            [46] = "RRSIG",
            [15] = "MX",
            [65422] = "XPF",
            [28] = "AAAA",
            [64] = "SVCB",
            [106] = "L64",
            [9] = "MR",
            [253] = "MAILB",
            [107] = "LP",
            [53] = "SMIMEA",
            [55] = "HIP",
            [52] = "TLSA",
            [251] = "IXFR",
            [21] = "RT",
            [4] = "MF",
            [12] = "PTR",
            [41] = "OPT",
            [58] = "TALINK",
            [17] = "RP",
            [105] = "L32",
            [254] = "MAILA",
            [32768] = "TA",
            [25] = "KEY",
            [32769] = "DLV",
            [65281] = "WINS",
            [29] = "LOC",
            [16] = "TXT",
            [255] = "*",
            [59] = "CDS",
            [38] = "A6",
            [252] = "AXFR",
            [63] = "ZONEMD",
            [42] = "APL",
            [57] = "RKEY",
            [1] = "A",
            [11] = "WKS",
            [35] = "NAPTR",
            [108] = "EUI48",
            [22] = "NSAP",
            [256] = "URI",
            [43] = "DS",
            [102] = "GID",
            [257] = "CAA",
            [65521] = "INTEGRITY",
            [3] = "MD",
            [44] = "SSHFP",
            [34] = "ATMA",
            [45] = "IPSECKEY",
            [40] = "SINK",
            [36] = "KX",
            [250] = "TSIG",
            [14] = "MINFO",
            [6] = "SOA",
            [31] = "EID",
            [23] = "NSAP-PTR",
            [8] = "MG",
            [27] = "GPOS",
            [56] = "NINFO",
            [7] = "MB",
            [10] = "NULL",
            [32] = "NIMLOC",
            [13] = "HINFO",
            [26] = "PX",
            [65] = "HTTPS",
            [62] = "CSYNC",
            [101] = "UID",
            [47] = "NSEC",
            [50] = "NSEC3",
            [2] = "NS",
            [65282] = "WINS-R",
            [48] = "DNSKEY",
            [24] = "SIG",
            [99] = "SPF",
            [49] = "DHCID",
            [109] = "EUI64",
            [249] = "TKEY",
            [103] = "UNSPEC",
            [5] = "CNAME",
            [104] = "NID",
            [61] = "OPENPGPKEY",
            [60] = "CDNSKEY",
            [100] = "UINFO",
            [51] = "NSEC3PARAM",
            [37] = "CERT",
            [18] = "AFSDB"
         }


   Mapping of DNS query type codes to human readable string
   representation.

.. zeek:id:: DNS::svcparam_keys
   :source-code: base/protocols/dns/consts.zeek 188 188

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "no-default-alpn",
            [3] = "port",
            [5] = "ech",
            [0] = "mandatory",
            [6] = "ipv6hint",
            [4] = "ipv4hint",
            [1] = "alpn"
         }


   SVCB/HTTPS SvcParam keys as defined in :rfc:`9460#name-initial-contents`.
   Keep in sync with src/analyzer/protocol/dns/DNS.h SVCPARAM_Key.


