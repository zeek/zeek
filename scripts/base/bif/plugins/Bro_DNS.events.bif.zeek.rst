:tocdepth: 3

base/bif/plugins/Bro_DNS.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== ================================================================================
:bro:id:`dns_A6_reply`: :bro:type:`event`      Generated for DNS replies of type *A6*.
:bro:id:`dns_AAAA_reply`: :bro:type:`event`    Generated for DNS replies of type *AAAA*.
:bro:id:`dns_A_reply`: :bro:type:`event`       Generated for DNS replies of type *A*.
:bro:id:`dns_CAA_reply`: :bro:type:`event`     Generated for DNS replies of type *CAA* (Certification Authority Authorization).
:bro:id:`dns_CNAME_reply`: :bro:type:`event`   Generated for DNS replies of type *CNAME*.
:bro:id:`dns_DNSKEY`: :bro:type:`event`        Generated for DNS replies of type *DNSKEY*.
:bro:id:`dns_DS`: :bro:type:`event`            Generated for DNS replies of type *DS*.
:bro:id:`dns_EDNS_addl`: :bro:type:`event`     Generated for DNS replies of type *EDNS*.
:bro:id:`dns_HINFO_reply`: :bro:type:`event`   Generated for DNS replies of type *HINFO*.
:bro:id:`dns_MX_reply`: :bro:type:`event`      Generated for DNS replies of type *MX*.
:bro:id:`dns_NSEC`: :bro:type:`event`          Generated for DNS replies of type *NSEC*.
:bro:id:`dns_NSEC3`: :bro:type:`event`         Generated for DNS replies of type *NSEC3*.
:bro:id:`dns_NS_reply`: :bro:type:`event`      Generated for DNS replies of type *NS*.
:bro:id:`dns_PTR_reply`: :bro:type:`event`     Generated for DNS replies of type *PTR*.
:bro:id:`dns_RRSIG`: :bro:type:`event`         Generated for DNS replies of type *RRSIG*.
:bro:id:`dns_SOA_reply`: :bro:type:`event`     Generated for DNS replies of type *CNAME*.
:bro:id:`dns_SRV_reply`: :bro:type:`event`     Generated for DNS replies of type *SRV*.
:bro:id:`dns_TSIG_addl`: :bro:type:`event`     Generated for DNS replies of type *TSIG*.
:bro:id:`dns_TXT_reply`: :bro:type:`event`     Generated for DNS replies of type *TXT*.
:bro:id:`dns_WKS_reply`: :bro:type:`event`     Generated for DNS replies of type *WKS*.
:bro:id:`dns_end`: :bro:type:`event`           Generated at the end of processing a DNS packet.
:bro:id:`dns_full_request`: :bro:type:`event`  Deprecated.
:bro:id:`dns_message`: :bro:type:`event`       Generated for all DNS messages.
:bro:id:`dns_query_reply`: :bro:type:`event`   Generated for each entry in the Question section of a DNS reply.
:bro:id:`dns_rejected`: :bro:type:`event`      Generated for DNS replies that reject a query.
:bro:id:`dns_request`: :bro:type:`event`       Generated for DNS requests.
:bro:id:`dns_unknown_reply`: :bro:type:`event` Generated on DNS reply resource records when the type of record is not one
                                               that Bro knows how to parse and generate another more specific event.
:bro:id:`non_dns_request`: :bro:type:`event`   msg: The raw DNS payload.
============================================== ================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: dns_A6_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *A6*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see::  dns_A_reply dns_AAAA_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_AAAA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *AAAA*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see::  dns_A_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_A_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *A*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_CAA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, flags: :bro:type:`count`, tag: :bro:type:`string`, value: :bro:type:`string`)

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

.. bro:id:: dns_CNAME_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply  dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_DNSKEY

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, dnskey: :bro:type:`dns_dnskey_rr`)

   Generated for DNS replies of type *DNSKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :dnskey: The parsed DNSKEY record.

.. bro:id:: dns_DS

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, ds: :bro:type:`dns_ds_rr`)

   Generated for DNS replies of type *DS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :ds: The parsed RDATA of DS record.

.. bro:id:: dns_EDNS_addl

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_edns_additional`)

   Generated for DNS replies of type *EDNS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed EDNS reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_HINFO_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated for DNS replies of type *HINFO*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_MX_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`, preference: :bro:type:`count`)

   Generated for DNS replies of type *MX*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   

   :preference: The preference for *name* specified by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply  dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_NSEC

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, next_name: :bro:type:`string`, bitmaps: :bro:type:`string_vec`)

   Generated for DNS replies of type *NSEC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :next_name: The parsed next secure domain name.
   

   :bitmaps: vector of strings in hex for the bit maps present.

.. bro:id:: dns_NSEC3

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, nsec3: :bro:type:`dns_nsec3_rr`)

   Generated for DNS replies of type *NSEC3*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :nsec3: The parsed RDATA of Nsec3 record.

.. bro:id:: dns_NS_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *NS*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply  dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_PTR_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *PTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply  dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_RRSIG

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, rrsig: :bro:type:`dns_rrsig_rr`)

   Generated for DNS replies of type *RRSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :rrsig: The parsed RRSIG record.

.. bro:id:: dns_SOA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, soa: :bro:type:`dns_soa`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :soa: The parsed SOA value.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_SRV_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, target: :bro:type:`string`, priority: :bro:type:`count`, weight: :bro:type:`count`, p: :bro:type:`count`)

   Generated for DNS replies of type *SRV*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
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
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_TSIG_addl

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_tsig_additional`)

   Generated for DNS replies of type *TSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed TSIG reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply  dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_TXT_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, strs: :bro:type:`string_vec`)

   Generated for DNS replies of type *TXT*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :strs: The textual information returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_WKS_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated for DNS replies of type *WKS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply  dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_end

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`)

   Generated at the end of processing a DNS packet. This event is the last
   ``dns_*`` event that will be raised for a DNS query/reply and signals that
   all resource records have been passed on.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_full_request

   :Type: :bro:type:`event` ()

   Deprecated. Will be removed.
   
   .. todo:: Unclear what this event is for; it's never raised. We should just
      remove it.

.. bro:id:: dns_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`dns_msg`, len: :bro:type:`count`)

   Generated for all DNS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :is_orig:  True if the message was sent by the originator of the connection.
   

   :msg: The parsed DNS message header.
   

   :len: The length of the message's raw representation (i.e., the DNS payload).
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid  dns_query_reply dns_rejected
      dns_request non_dns_request  dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_query_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for each entry in the Question section of a DNS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_rejected
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_rejected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for DNS replies that reject a query. This event is raised if a DNS
   reply indicates failure because it does not pass on any
   answers to a query. Note that all of the event's parameters are parsed out of
   the reply; there's no stateful correlation with the query.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for DNS requests. For requests with multiple queries, this event
   is raised once for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_unknown_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated on DNS reply resource records when the type of record is not one
   that Bro knows how to parse and generate another more specific event.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_SRV_reply dns_end

.. bro:id:: non_dns_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)


   :msg: The raw DNS payload.
   
   .. note:: This event is deprecated and superseded by Bro's dynamic protocol
      detection framework.


