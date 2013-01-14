
connection GTPv1_Conn(bro_analyzer: BroAnalyzer)
	{
	upflow = GTPv1_Flow(true);
	downflow = GTPv1_Flow(false);

	%member{
		bool valid_orig;
		bool valid_resp;
	%}

	%init{
		valid_orig = valid_resp = false;
	%}

	function valid(orig: bool): bool
		%{
		return orig ? valid_orig : valid_resp;
		%}

	function set_valid(orig: bool, val: bool): void
		%{
		if ( orig )
			valid_orig = val;
		else
			valid_resp = val;
		%}
	}

%code{
inline void violate(const char* r, const BroAnalyzer& a, const bytestring& p)
	{
	a->ProtocolViolation(r, (const char*) p.data(), p.length());
	}
%}

flow GTPv1_Flow(is_orig: bool)
	{
	datagram = GTPv1_Header withcontext(connection, this);

	function process_gtpv1(pdu: GTPv1_Header): bool
		%{
		BroAnalyzer a = connection()->bro_analyzer();
		Connection *c = a->Conn();
		const EncapsulationStack* e = c->GetEncapsulation();

		connection()->set_valid(is_orig(), false);

		if ( e && e->Depth() >= BifConst::Tunnel::max_depth )
			{
			reporter->Weird(c, "tunnel_depth");
			return false;
			}

		if ( e && e->LastType() == BifEnum::Tunnel::GTPv1 )
			{
			// GTP is never tunneled in GTP so, this must be a regular packet
			violate("GTP-in-GTP", a, ${pdu.packet});
			return false;
			}

		if ( ${pdu.version} != 1 )
			{
			// Only know of GTPv1 with Version == 1
			violate("GTPv1 bad Version", a, ${pdu.packet});
			return false;
			}

		if ( ! ${pdu.pt_flag} )
			{
			// Not interested in GTP'
			return false;
			}

		if ( ${pdu.e_flag} )
			{
			// TODO: can't currently parse past extension headers
			return false;
			}

		if ( ${pdu.msg_type} != 0xff )
			{
			// Only interested in decapsulating user plane data beyond here.
			return false;
			}

		if ( ${pdu.packet}.length() < (int)sizeof(struct ip) )
			{
			violate("Truncated GTPv1", a, ${pdu.packet});
			return false;
			}

		const struct ip* ip = (const struct ip*) ${pdu.packet}.data();

		if ( ip->ip_v != 4 && ip->ip_v != 6 )
			{
			violate("non-IP packet in GTPv1", a, ${pdu.packet});
			return false;
			}

		IP_Hdr* inner = 0;
		int result = sessions->ParseIPPacket(${pdu.packet}.length(),
		     ${pdu.packet}.data(), ip->ip_v == 6 ? IPPROTO_IPV6 : IPPROTO_IPV4,
		     inner);

		if ( result == 0 )
			{
			connection()->set_valid(is_orig(), true);

			if ( (! BifConst::Tunnel::delay_gtp_confirmation) ||
			     (connection()->valid(true) && connection()->valid(false)) )
				a->ProtocolConfirmation();
			}

		else if ( result < 0 )
			violate("Truncated GTPv1", a, ${pdu.packet});

		else
			violate("GTPv1 payload length", a, ${pdu.packet});

		if ( result != 0 )
			{
			delete inner;
			return false;
			}

		if ( ::gtpv1_g_pdu_packet )
			{
			RecordVal* rv = new RecordVal(gtpv1_hdr_type);

			rv->Assign(0, new Val(${pdu.version}, TYPE_COUNT));
			rv->Assign(1, new Val(${pdu.pt_flag}, TYPE_BOOL));
			rv->Assign(2, new Val(${pdu.rsv}, TYPE_BOOL));
			rv->Assign(3, new Val(${pdu.e_flag}, TYPE_BOOL));
			rv->Assign(4, new Val(${pdu.s_flag}, TYPE_BOOL));
			rv->Assign(5, new Val(${pdu.pn_flag}, TYPE_BOOL));
			rv->Assign(6, new Val(${pdu.msg_type}, TYPE_COUNT));
			rv->Assign(7, new Val(ntohs(${pdu.length}), TYPE_COUNT));
			rv->Assign(8, new Val(ntohl(${pdu.teid}), TYPE_COUNT));

			if ( ${pdu.has_opt} )
				{
				rv->Assign(9, new Val(ntohs(${pdu.opt_hdr.seq}), TYPE_COUNT));
				rv->Assign(10, new Val(${pdu.opt_hdr.n_pdu}, TYPE_COUNT));
				rv->Assign(11, new Val(${pdu.opt_hdr.next_type}, TYPE_COUNT));
				}

			BifEvent::generate_gtpv1_g_pdu_packet(a, c, rv,
			                                      inner->BuildPktHdrVal());
			}

		EncapsulatingConn ec(c, BifEnum::Tunnel::GTPv1);

		sessions->DoNextInnerPacket(network_time(), 0, inner, e, ec);

		return (result == 0) ? true : false;
		%}

	};

refine typeattr GTPv1_Header += &let { proc_gtpv1 = $context.flow.process_gtpv1(this); };
