:tocdepth: 3

base/bif/plugins/Zeek_DNS.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
===================================================== =======================================================================================
:zeek:id:`dns_A6_reply`: :zeek:type:`event`           Generated for DNS replies of type *A6*.
:zeek:id:`dns_AAAA_reply`: :zeek:type:`event`         Generated for DNS replies of type *AAAA*.
:zeek:id:`dns_A_reply`: :zeek:type:`event`            Generated for DNS replies of type *A*.
:zeek:id:`dns_BINDS`: :zeek:type:`event`              Generated for DNS replies of type *BINDS*.
:zeek:id:`dns_CAA_reply`: :zeek:type:`event`          Generated for DNS replies of type *CAA* (Certification Authority Authorization).
:zeek:id:`dns_CNAME_reply`: :zeek:type:`event`        Generated for DNS replies of type *CNAME*.
:zeek:id:`dns_DNSKEY`: :zeek:type:`event`             Generated for DNS replies of type *DNSKEY*.
:zeek:id:`dns_DS`: :zeek:type:`event`                 Generated for DNS replies of type *DS*.
:zeek:id:`dns_EDNS_addl`: :zeek:type:`event`          Generated for DNS replies of type *EDNS*.
:zeek:id:`dns_EDNS_cookie`: :zeek:type:`event`        Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
                                                      an opt-type of 10.
:zeek:id:`dns_EDNS_ecs`: :zeek:type:`event`           Generated for DNS replies of type *EDNS*.
:zeek:id:`dns_EDNS_tcp_keepalive`: :zeek:type:`event` Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
                                                      an opt-type of 11.
:zeek:id:`dns_HINFO_reply`: :zeek:type:`event`        Generated for DNS replies of type *HINFO*.
:zeek:id:`dns_HTTPS`: :zeek:type:`event`              Generated for DNS replies of type *HTTPS* (HTTPS Specific Service Endpoints).
:zeek:id:`dns_LOC`: :zeek:type:`event`                Generated for DNS replies of type *LOC*.
:zeek:id:`dns_MX_reply`: :zeek:type:`event`           Generated for DNS replies of type *MX*.
:zeek:id:`dns_NAPTR_reply`: :zeek:type:`event`        Generated for DNS replies of type *NAPTR*.
:zeek:id:`dns_NSEC`: :zeek:type:`event`               Generated for DNS replies of type *NSEC*.
:zeek:id:`dns_NSEC3`: :zeek:type:`event`              Generated for DNS replies of type *NSEC3*.
:zeek:id:`dns_NSEC3PARAM`: :zeek:type:`event`         Generated for DNS replies of type *NSEC3PARAM*.
:zeek:id:`dns_NS_reply`: :zeek:type:`event`           Generated for DNS replies of type *NS*.
:zeek:id:`dns_PTR_reply`: :zeek:type:`event`          Generated for DNS replies of type *PTR*.
:zeek:id:`dns_RRSIG`: :zeek:type:`event`              Generated for DNS replies of type *RRSIG*.
:zeek:id:`dns_SOA_reply`: :zeek:type:`event`          Generated for DNS replies of type *CNAME*.
:zeek:id:`dns_SPF_reply`: :zeek:type:`event`          Generated for DNS replies of type *SPF*.
:zeek:id:`dns_SRV_reply`: :zeek:type:`event`          Generated for DNS replies of type *SRV*.
:zeek:id:`dns_SSHFP`: :zeek:type:`event`              Generated for DNS replies of type *BINDS*.
:zeek:id:`dns_SVCB`: :zeek:type:`event`               Generated for DNS replies of type *SVCB* (General Purpose Service Endpoints).
:zeek:id:`dns_TKEY`: :zeek:type:`event`               Generated for DNS replies of type *TKEY*.
:zeek:id:`dns_TSIG_addl`: :zeek:type:`event`          Generated for DNS replies of type *TSIG*.
:zeek:id:`dns_TXT_reply`: :zeek:type:`event`          Generated for DNS replies of type *TXT*.
:zeek:id:`dns_WKS_reply`: :zeek:type:`event`          Generated for DNS replies of type *WKS*.
:zeek:id:`dns_dynamic_update`: :zeek:type:`event`     Generated for DNS Dynamic Update messages.
:zeek:id:`dns_dynamic_update_del`: :zeek:type:`event` Generated for deletions found in the update section of DNS Dynamic update messages.
:zeek:id:`dns_dynamic_update_pre`: :zeek:type:`event` Generated for RRs found in the pre-requisites section of DNS Dynamic update messages.
:zeek:id:`dns_end`: :zeek:type:`event`                Generated at the end of processing a DNS packet.
:zeek:id:`dns_message`: :zeek:type:`event`            Generated for all DNS messages.
:zeek:id:`dns_query_reply`: :zeek:type:`event`        Generated for each entry in the Question section of a DNS reply.
:zeek:id:`dns_rejected`: :zeek:type:`event`           Generated for DNS replies that reject a query.
:zeek:id:`dns_request`: :zeek:type:`event`            Generated for DNS requests.
:zeek:id:`dns_unknown_reply`: :zeek:type:`event`      Generated on DNS reply resource records when the type of record is not one
                                                      that Zeek knows how to parse and generate another more specific event.
===================================================== =======================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dns_A6_reply
   :source-code: base/protocols/dns/main.zeek 520 526

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A6*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_AAAA_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_AAAA_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 175 175

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *AAAA*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_A_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 149 149

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_BINDS
   :source-code: base/protocols/dns/main.zeek 642 645

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, binds: :zeek:type:`dns_binds_rr`)

   Generated for DNS replies of type *BINDS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param binds: The parsed RDATA of BIND-Signing state record.

.. zeek:id:: dns_CAA_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 453 453

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, flags: :zeek:type:`count`, tag: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for DNS replies of type *CAA* (Certification Authority Authorization).
   For replies with multiple answers, an individual event of the corresponding type
   is raised for each.
   See `RFC 6844 <https://datatracker.ietf.org/doc/html/rfc6844>`__ for more details.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param flags: The flags byte of the CAA reply.
   

   :param tag: The property identifier of the CAA reply.
   

   :param value: The property value of the CAA reply.

.. zeek:id:: dns_CNAME_reply
   :source-code: base/protocols/dns/main.zeek 533 536

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply  dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_DNSKEY
   :source-code: base/protocols/dns/main.zeek 613 618

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, dnskey: :zeek:type:`dns_dnskey_rr`)

   Generated for DNS replies of type *DNSKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param dnskey: The parsed DNSKEY record.

.. zeek:id:: dns_DS
   :source-code: base/protocols/dns/main.zeek 635 640

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, ds: :zeek:type:`dns_ds_rr`)

   Generated for DNS replies of type *DS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param ds: The parsed RDATA of DS record.

.. zeek:id:: dns_EDNS_addl
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 552 552

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_edns_additional`)

   Generated for DNS replies of type *EDNS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The parsed EDNS reply.
   
   .. note::
   
        Note that this event will only be raised if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_cookie
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 643 643

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_cookie`)

   Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
   an opt-type of 10. For replies with multiple options fields, an individual event
   is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. See `RFC7873 <https://datatracker.ietf.org/doc/html/rfc7873>`__ for
   more information about EDNS0 cookie. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS Cookie option.
   
   .. note::
   
        Note that this event will only be raised if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_ecs
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 581 581

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_ecs`)

   Generated for DNS replies of type *EDNS*. For replies with multiple options,
   an individual event is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS option.
   
   .. note::
   
        Note that this event will only be raised if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_tcp_keepalive
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 612 612

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_tcp_keepalive`)

   Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
   an opt-type of 11. For replies with multiple option fields, an individual event is
   raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. See `RFC7828 <https://datatracker.ietf.org/doc/html/rfc7828>`__ for
   more information about EDNS0 TCP keepalive. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS Keepalive option.
   
   .. note::
   
        Note that this event will only be raised if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_HINFO_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 353 353

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, cpu: :zeek:type:`string`, os: :zeek:type:`string`)

   Generated for DNS replies of type *HINFO*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_HTTPS
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 856 856

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, https: :zeek:type:`dns_svcb_rr`)

   Generated for DNS replies of type *HTTPS* (HTTPS Specific Service Endpoints).
   See `RFC draft for DNS SVCB/HTTPS <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-07>`__
   for more information about DNS SVCB/HTTPS resource records.
   Since SVCB and HTTPS records share the same wire format layout, the argument https is dns_svcb_rr.
   For replies with multiple answers, an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param https: The parsed RDATA of HTTPS type record.

.. zeek:id:: dns_LOC
   :source-code: base/protocols/dns/main.zeek 654 659

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, loc: :zeek:type:`dns_loc_rr`)

   Generated for DNS replies of type *LOC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param loc: The parsed RDATA of LOC type record.

.. zeek:id:: dns_MX_reply
   :source-code: base/protocols/dns/main.zeek 539 542

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`, preference: :zeek:type:`count`)

   Generated for DNS replies of type *MX*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   

   :param preference: The preference for *name* specified by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply  dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_NAPTR_reply
   :source-code: base/protocols/dns/main.zeek 564 583

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, naptr: :zeek:type:`dns_naptr_rr`)

   Generated for DNS replies of type *NAPTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param naptr: The parsed RDATA of NAPTR type record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_SRV_reply dns_end

.. zeek:id:: dns_NSEC
   :source-code: base/protocols/dns/main.zeek 620 623

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, next_name: :zeek:type:`string`, bitmaps: :zeek:type:`string_vec`)

   Generated for DNS replies of type *NSEC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param next_name: The parsed next secure domain name.
   

   :param bitmaps: vector of strings in hex for the bit maps present.

.. zeek:id:: dns_NSEC3
   :source-code: base/protocols/dns/main.zeek 625 628

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, nsec3: :zeek:type:`dns_nsec3_rr`)

   Generated for DNS replies of type *NSEC3*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param nsec3: The parsed RDATA of Nsec3 record.

.. zeek:id:: dns_NSEC3PARAM
   :source-code: base/protocols/dns/main.zeek 630 633

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, nsec3param: :zeek:type:`dns_nsec3param_rr`)

   Generated for DNS replies of type *NSEC3PARAM*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param nsec3param: The parsed RDATA of NSEC3PARAM record.

.. zeek:id:: dns_NS_reply
   :source-code: base/protocols/dns/main.zeek 528 531

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *NS*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply  dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_PTR_reply
   :source-code: base/protocols/dns/main.zeek 544 547

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *PTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply  dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_RRSIG
   :source-code: base/protocols/dns/main.zeek 605 611

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, rrsig: :zeek:type:`dns_rrsig_rr`)

   Generated for DNS replies of type *RRSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param rrsig: The parsed RRSIG record.

.. zeek:id:: dns_SOA_reply
   :source-code: base/protocols/dns/main.zeek 549 552

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, soa: :zeek:type:`dns_soa`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param soa: The parsed SOA value.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SPF_reply
   :source-code: base/protocols/dns/main.zeek 497 510

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, strs: :zeek:type:`string_vec`)

   Generated for DNS replies of type *SPF*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param strs: The textual information returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SRV_reply
   :source-code: base/protocols/dns/main.zeek 559 562

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, target: :zeek:type:`string`, priority: :zeek:type:`count`, weight: :zeek:type:`count`, p: :zeek:type:`count`)

   Generated for DNS replies of type *SRV*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param target: Target of the SRV response -- the canonical hostname of the
           machine providing the service, ending in a dot.
   

   :param priority: Priority of the SRV response -- the priority of the target
             host, lower value means more preferred.
   

   :param weight: Weight of the SRV response -- a relative weight for records
           with the same priority, higher value means more preferred.
   

   :param p: Port of the SRV response -- the TCP or UDP port on which the
      service is to be found.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SSHFP
   :source-code: base/protocols/dns/main.zeek 647 652

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, algo: :zeek:type:`count`, fptype: :zeek:type:`count`, fingerprint: :zeek:type:`string`)

   Generated for DNS replies of type *BINDS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param binds: The parsed RDATA of BIND-Signing state record.

.. zeek:id:: dns_SVCB
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 839 839

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, svcb: :zeek:type:`dns_svcb_rr`)

   Generated for DNS replies of type *SVCB* (General Purpose Service Endpoints).
   See `RFC draft for DNS SVCB/HTTPS <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-07>`__
   for more information about DNS SVCB/HTTPS resource records.
   For replies with multiple answers, an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param svcb: The parsed RDATA of SVCB type record.

.. zeek:id:: dns_TKEY
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 666 666

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_tkey`)

   Generated for DNS replies of type *TKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. See `RFC2930 <https://datatracker.ietf.org/doc/html/rfc2930>`__
   for more information about TKEY. Zeek analyzes both UDP and TCP DNS sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The parsed TKEY reply.
   
   .. note::
   
        Note that ``ans`` will only be populated if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_TSIG_addl

.. zeek:id:: dns_TSIG_addl
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 695 695

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_tsig_additional`)

   Generated for DNS replies of type *TSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The parsed TSIG reply.
   
   .. note::
   
        Note that this event will only be raised if :zeek:see:`dns_skip_all_addl`
        is set to false.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply  dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_TXT_reply
   :source-code: base/protocols/dns/main.zeek 482 495

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, strs: :zeek:type:`string_vec`)

   Generated for DNS replies of type *TXT*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param strs: The textual information returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_WKS_reply
   :source-code: base/protocols/dns/main.zeek 554 557

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for DNS replies of type *WKS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply  dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_dynamic_update
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 893 893

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, zname: :zeek:type:`string`, zclass: :zeek:type:`count`)

   Generated for DNS Dynamic Update messages. See :rfc:`2136` for more information
   about Dynamic Updates.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param zname: The name from the Zone section of the message.
   

   :param zclass: The class from the Zone section of the message.

.. zeek:id:: dns_dynamic_update_del
   :source-code: base/protocols/dns/main.zeek 687 703

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for deletions found in the update section of DNS Dynamic update messages.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The RR parsed from the dynamic update.
   

.. zeek:id:: dns_dynamic_update_pre
   :source-code: base/protocols/dns/main.zeek 667 685

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for RRs found in the pre-requisites section of DNS Dynamic update messages.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The RR parsed from the dynamic update.
   

.. zeek:id:: dns_end
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 879 879

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`)

   Generated at the end of processing a DNS packet. This event is the last
   ``dns_*`` event that will be raised for a DNS query/reply and signals that
   all resource records have been passed on.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_message
   :source-code: base/protocols/dns/main.zeek 358 365

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`dns_msg`, len: :zeek:type:`count`)

   Generated for all DNS messages.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param is_orig:  True if the message was sent by the originator of the connection.
   

   :param msg: The parsed DNS message header.
   

   :param len: The length of the message's raw representation (i.e., the DNS payload).
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid  dns_query_reply dns_rejected
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_query_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 121 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for each entry in the Question section of a DNS reply.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name.
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_rejected
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_rejected
   :source-code: base/protocols/dns/main.zeek 661 665

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS replies that reject a query. This event is raised if a DNS
   reply indicates failure because it does not pass on any
   answers to a query. Note that all of the event's parameters are parsed out of
   the reply; there's no stateful correlation with the query.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name (normalized to all lowercase).
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_request
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS requests. For requests with multiple queries, this event
   is raised once for each.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name (normalized to all lowercase).
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_unknown_reply
   :source-code: base/protocols/dns/main.zeek 469 472

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated on DNS reply resource records when the type of record is not one
   that Zeek knows how to parse and generate another more specific event.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_SRV_reply dns_end


