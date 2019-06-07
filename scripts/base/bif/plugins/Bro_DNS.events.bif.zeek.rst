:tocdepth: 3

base/bif/plugins/Bro_DNS.events.bif.zeek
========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ ================================================================================
:zeek:id:`dns_A6_reply`: :zeek:type:`event`      Generated for DNS replies of type *A6*.
:zeek:id:`dns_AAAA_reply`: :zeek:type:`event`    Generated for DNS replies of type *AAAA*.
:zeek:id:`dns_A_reply`: :zeek:type:`event`       Generated for DNS replies of type *A*.
:zeek:id:`dns_CAA_reply`: :zeek:type:`event`     Generated for DNS replies of type *CAA* (Certification Authority Authorization).
:zeek:id:`dns_CNAME_reply`: :zeek:type:`event`   Generated for DNS replies of type *CNAME*.
:zeek:id:`dns_DNSKEY`: :zeek:type:`event`        Generated for DNS replies of type *DNSKEY*.
:zeek:id:`dns_DS`: :zeek:type:`event`            Generated for DNS replies of type *DS*.
:zeek:id:`dns_EDNS_addl`: :zeek:type:`event`     Generated for DNS replies of type *EDNS*.
:zeek:id:`dns_HINFO_reply`: :zeek:type:`event`   Generated for DNS replies of type *HINFO*.
:zeek:id:`dns_MX_reply`: :zeek:type:`event`      Generated for DNS replies of type *MX*.
:zeek:id:`dns_NSEC`: :zeek:type:`event`          Generated for DNS replies of type *NSEC*.
:zeek:id:`dns_NSEC3`: :zeek:type:`event`         Generated for DNS replies of type *NSEC3*.
:zeek:id:`dns_NS_reply`: :zeek:type:`event`      Generated for DNS replies of type *NS*.
:zeek:id:`dns_PTR_reply`: :zeek:type:`event`     Generated for DNS replies of type *PTR*.
:zeek:id:`dns_RRSIG`: :zeek:type:`event`         Generated for DNS replies of type *RRSIG*.
:zeek:id:`dns_SOA_reply`: :zeek:type:`event`     Generated for DNS replies of type *CNAME*.
:zeek:id:`dns_SRV_reply`: :zeek:type:`event`     Generated for DNS replies of type *SRV*.
:zeek:id:`dns_TSIG_addl`: :zeek:type:`event`     Generated for DNS replies of type *TSIG*.
:zeek:id:`dns_TXT_reply`: :zeek:type:`event`     Generated for DNS replies of type *TXT*.
:zeek:id:`dns_WKS_reply`: :zeek:type:`event`     Generated for DNS replies of type *WKS*.
:zeek:id:`dns_end`: :zeek:type:`event`           Generated at the end of processing a DNS packet.
:zeek:id:`dns_full_request`: :zeek:type:`event`  Deprecated.
:zeek:id:`dns_message`: :zeek:type:`event`       Generated for all DNS messages.
:zeek:id:`dns_query_reply`: :zeek:type:`event`   Generated for each entry in the Question section of a DNS reply.
:zeek:id:`dns_rejected`: :zeek:type:`event`      Generated for DNS replies that reject a query.
:zeek:id:`dns_request`: :zeek:type:`event`       Generated for DNS requests.
:zeek:id:`dns_unknown_reply`: :zeek:type:`event` Generated on DNS reply resource records when the type of record is not one
                                                 that Zeek knows how to parse and generate another more specific event.
:zeek:id:`non_dns_request`: :zeek:type:`event`   msg: The raw DNS payload.
================================================ ================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dns_A6_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A6*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_AAAA_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_AAAA_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *AAAA*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_A_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_CAA_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, flags: :zeek:type:`count`, tag: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for DNS replies of type *CAA* (Certification Authority Authorization).
   For replies with multiple answers, an individual event of the corresponding type
   is raised for each.
   See `RFC 6844 <https://tools.ietf.org/html/rfc6844>`__ for more details.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :flags: The flags byte of the CAA reply.
   

   :tag: The property identifier of the CAA reply.
   

   :value: The property value of the CAA reply.

.. zeek:id:: dns_CNAME_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply  dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_DNSKEY

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, dnskey: :zeek:type:`dns_dnskey_rr`)

   Generated for DNS replies of type *DNSKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :dnskey: The parsed DNSKEY record.

.. zeek:id:: dns_DS

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, ds: :zeek:type:`dns_ds_rr`)

   Generated for DNS replies of type *DS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :ds: The parsed RDATA of DS record.

.. zeek:id:: dns_EDNS_addl

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_edns_additional`)

   Generated for DNS replies of type *EDNS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed EDNS reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_HINFO_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for DNS replies of type *HINFO*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_MX_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`, preference: :zeek:type:`count`)

   Generated for DNS replies of type *MX*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   

   :preference: The preference for *name* specified by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply  dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_NSEC

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, next_name: :zeek:type:`string`, bitmaps: :zeek:type:`string_vec`)

   Generated for DNS replies of type *NSEC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :next_name: The parsed next secure domain name.
   

   :bitmaps: vector of strings in hex for the bit maps present.

.. zeek:id:: dns_NSEC3

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, nsec3: :zeek:type:`dns_nsec3_rr`)

   Generated for DNS replies of type *NSEC3*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :nsec3: The parsed RDATA of Nsec3 record.

.. zeek:id:: dns_NS_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *NS*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply  dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_PTR_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *PTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply  dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_RRSIG

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, rrsig: :zeek:type:`dns_rrsig_rr`)

   Generated for DNS replies of type *RRSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :rrsig: The parsed RRSIG record.

.. zeek:id:: dns_SOA_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, soa: :zeek:type:`dns_soa`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :soa: The parsed SOA value.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SRV_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, target: :zeek:type:`string`, priority: :zeek:type:`count`, weight: :zeek:type:`count`, p: :zeek:type:`count`)

   Generated for DNS replies of type *SRV*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :target: Target of the SRV response -- the canonical hostname of the
           machine providing the service, ending in a dot.
   

   :priority: Priority of the SRV response -- the priority of the target
             host, lower value means more preferred.
   

   :weight: Weight of the SRV response -- a relative weight for records
           with the same priority, higher value means more preferred.
   

   :p: Port of the SRV response -- the TCP or UDP port on which the
      service is to be found.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_TSIG_addl

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_tsig_additional`)

   Generated for DNS replies of type *TSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed TSIG reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply  dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_TXT_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, strs: :zeek:type:`string_vec`)

   Generated for DNS replies of type *TXT*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :strs: The textual information returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_WKS_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for DNS replies of type *WKS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply  dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_end

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`)

   Generated at the end of processing a DNS packet. This event is the last
   ``dns_*`` event that will be raised for a DNS query/reply and signals that
   all resource records have been passed on.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_full_request

   :Type: :zeek:type:`event` ()

   Deprecated. Will be removed.
   
   .. todo:: Unclear what this event is for; it's never raised. We should just
      remove it.

.. zeek:id:: dns_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`dns_msg`, len: :zeek:type:`count`)

   Generated for all DNS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :is_orig:  True if the message was sent by the originator of the connection.
   

   :msg: The parsed DNS message header.
   

   :len: The length of the message's raw representation (i.e., the DNS payload).
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid  dns_query_reply dns_rejected
      dns_request non_dns_request  dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_query_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for each entry in the Question section of a DNS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_rejected
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_rejected

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS replies that reject a query. This event is raised if a DNS
   reply indicates failure because it does not pass on any
   answers to a query. Note that all of the event's parameters are parsed out of
   the reply; there's no stateful correlation with the query.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS requests. For requests with multiple queries, this event
   is raised once for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_unknown_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated on DNS reply resource records when the type of record is not one
   that Zeek knows how to parse and generate another more specific event.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_SRV_reply dns_end

.. zeek:id:: non_dns_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)


   :msg: The raw DNS payload.
   
   .. note:: This event is deprecated and superseded by Zeek's dynamic protocol
      detection framework.


