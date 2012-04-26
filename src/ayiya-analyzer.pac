
connection AYIYA_Conn(bro_analyzer: BroAnalyzer)
	{
	upflow = AYIYA_Flow;
	downflow = AYIYA_Flow;
	};

flow AYIYA_Flow
	{
	datagram = PDU withcontext(connection, this);
	
	function process_ayiya(pdu: PDU): bool
		%{
		Connection *c = connection()->bro_analyzer()->Conn();
		
		if ( c->GetEncapsulation().Depth() >= BifConst::Tunnel::max_depth )
			{
			reporter->Weird(c, "tunnel_depth");
			return false;
			}
		
		if ( ${pdu.op} != 1 )
			{
			// 1 is the "forward" command.
			return false;
			}
		
		IP_Hdr* inner_ip;
		if ( ${pdu.next_header} == IPPROTO_IPV6 )
			inner_ip = new IP_Hdr((const struct ip6_hdr*) ${pdu.packet}.data(), false, ${pdu.packet}.length());
		else if ( ${pdu.next_header} == IPPROTO_IPV4 )
			inner_ip = new IP_Hdr((const struct ip*) ${pdu.packet}.data(), false);
		else
			{
			reporter->Weird(c, "ayiya_tunnel_non_ip");
			return false;
			}
		
		connection()->bro_analyzer()->ProtocolConfirmation();
		
		struct pcap_pkthdr fake_hdr;
		fake_hdr.caplen = fake_hdr.len = ${pdu.packet}.length();
		fake_hdr.ts.tv_sec = fake_hdr.ts.tv_usec = 0;
		
		Encapsulation encap(c->GetEncapsulation());
		EncapsulatingConn ec(c, BifEnum::Tunnel::AYIYA);
		encap.Add(ec);
		
		sessions->DoNextPacket(network_time(), &fake_hdr, inner_ip, ${pdu.packet}.data(), 0, encap);
		
		delete inner_ip;
		return true;
		%}

	};

refine typeattr PDU += &let {
	proc_ayiya = $context.flow.process_ayiya(this);
};
