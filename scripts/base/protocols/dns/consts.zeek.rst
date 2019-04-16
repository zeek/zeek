:tocdepth: 3

base/protocols/dns/consts.zeek
==============================
.. bro:namespace:: DNS

Types, errors, and fields for analyzing DNS data.  A helper file
for DNS analysis scripts.

:Namespace: DNS

Summary
~~~~~~~
Constants
#########
=============================================================================================================== ======================================================================
:bro:id:`DNS::ANY`: :bro:type:`count`                                                                           A QTYPE value describing a request for all records.
:bro:id:`DNS::EDNS`: :bro:type:`count`                                                                          An OPT RR TYPE value described by EDNS.
:bro:id:`DNS::PTR`: :bro:type:`count`                                                                           RR TYPE value for a domain name pointer.
:bro:id:`DNS::algorithms`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`  Possible values of the algorithms used in DNSKEY, DS and RRSIG records
:bro:id:`DNS::base_errors`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` Errors used for non-TSIG/EDNS types.
:bro:id:`DNS::classes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`     Possible values of the CLASS field in resource records or QCLASS
                                                                                                                field in query messages.
:bro:id:`DNS::digests`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`     Possible digest types used in DNSSEC.
:bro:id:`DNS::edns_zfield`: :bro:type:`table` :bro:attr:`&default` = ``"?"`` :bro:attr:`&optional`              This deciphers EDNS Z field values.
:bro:id:`DNS::query_types`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` Mapping of DNS query type codes to human readable string
                                                                                                                representation.
=============================================================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: DNS::ANY

   :Type: :bro:type:`count`
   :Default: ``255``

   A QTYPE value describing a request for all records.

.. bro:id:: DNS::EDNS

   :Type: :bro:type:`count`
   :Default: ``41``

   An OPT RR TYPE value described by EDNS.

.. bro:id:: DNS::PTR

   :Type: :bro:type:`count`
   :Default: ``12``

   RR TYPE value for a domain name pointer.

.. bro:id:: DNS::algorithms

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "Diffie_Hellman",
         [6] = "DSA_NSEC3_SHA1",
         [14] = "ECDSA_curveP384withSHA384",
         [4] = "Elliptic_Curve",
         [1] = "RSA_MD5",
         [8] = "RSA_SHA256",
         [7] = "RSA_SHA1_NSEC3_SHA1",
         [15] = "Ed25519",
         [252] = "Indirect",
         [254] = "PrivateOID",
         [255] = "reserved255",
         [5] = "RSA_SHA1",
         [10] = "RSA_SHA512",
         [253] = "PrivateDNS",
         [0] = "reserved0",
         [3] = "DSA_SHA1",
         [12] = "GOST_R_34_10_2001",
         [13] = "ECDSA_curveP256withSHA256",
         [16] = "Ed448"
      }

   Possible values of the algorithms used in DNSKEY, DS and RRSIG records

.. bro:id:: DNS::base_errors

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "SERVFAIL",
         [9] = "NOTAUTH",
         [17] = "BADKEY",
         [6] = "YXDOMAIN",
         [11] = "unassigned-11",
         [14] = "unassigned-14",
         [4] = "NOTIMP",
         [22] = "BADTRUNC",
         [1] = "FORMERR",
         [8] = "NXRRSet",
         [3842] = "BADSIG",
         [7] = "YXRRSET",
         [15] = "unassigned-15",
         [5] = "REFUSED",
         [19] = "BADMODE",
         [10] = "NOTZONE",
         [0] = "NOERROR",
         [3] = "NXDOMAIN",
         [12] = "unassigned-12",
         [13] = "unassigned-13",
         [18] = "BADTIME",
         [21] = "BADALG",
         [16] = "BADVERS",
         [20] = "BADNAME"
      }

   Errors used for non-TSIG/EDNS types.

.. bro:id:: DNS::classes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "C_CSNET",
         [4] = "C_HESOD",
         [1] = "C_INTERNET",
         [254] = "C_NONE",
         [255] = "C_ANY",
         [3] = "C_CHAOS"
      }

   Possible values of the CLASS field in resource records or QCLASS
   field in query messages.

.. bro:id:: DNS::digests

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "SHA256",
         [4] = "SHA384",
         [1] = "SHA1",
         [0] = "reserved0",
         [3] = "GOST_R_34_11_94"
      }

   Possible digest types used in DNSSEC.

.. bro:id:: DNS::edns_zfield

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = ``"?"`` :bro:attr:`&optional`
   :Default:

   ::

      {
         [32768] = "DNS_SEC_OK",
         [0] = "NOVALUE"
      }

   This deciphers EDNS Z field values.

.. bro:id:: DNS::query_types

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [19] = "X25",
         [10] = "NULL",
         [3] = "MD",
         [254] = "MAILA",
         [43] = "DS",
         [50] = "NSEC3",
         [99] = "SPF",
         [47] = "NSEC",
         [251] = "IXFR",
         [32768] = "TA",
         [27] = "GPOS",
         [6] = "SOA",
         [20] = "ISDN",
         [51] = "NSEC3PARAM",
         [25] = "KEY",
         [37] = "CERT",
         [31] = "NIMLOC",
         [28] = "AAAA",
         [9] = "MR",
         [32769] = "DLV",
         [11] = "WKS",
         [40] = "SINK",
         [41] = "OPT",
         [59] = "CDS",
         [252] = "AXFR",
         [46] = "RRSIG",
         [5] = "CNAME",
         [49] = "DHCID",
         [103] = "UNSPEC",
         [253] = "MAILB",
         [45] = "IPSECKEY",
         [8] = "MG",
         [17] = "RP",
         [48] = "DNSKEY",
         [257] = "CAA",
         [33] = "SRV",
         [100] = "UINFO",
         [24] = "SIG",
         [23] = "NSAP-PTR",
         [26] = "PX",
         [101] = "UID",
         [39] = "DNAME",
         [16] = "TXT",
         [34] = "ATMA",
         [38] = "A6",
         [18] = "AFSDB",
         [35] = "NAPTR",
         [42] = "APL",
         [7] = "MB",
         [15] = "MX",
         [249] = "TKEY",
         [36] = "KX",
         [4] = "MF",
         [44] = "SSHFP",
         [52] = "TLSA",
         [1] = "A",
         [22] = "NSAP",
         [250] = "TSIG",
         [14] = "MINFO",
         [102] = "GID",
         [255] = "*",
         [256] = "URI",
         [21] = "RT",
         [29] = "LOC",
         [13] = "HINFO",
         [30] = "EID",
         [55] = "HIP",
         [2] = "NS",
         [32] = "NB",
         [60] = "CDNSKEY",
         [12] = "PTR",
         [61] = "OPENPGPKEY"
      }

   Mapping of DNS query type codes to human readable string
   representation.


