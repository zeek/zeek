
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
		
		if ( c->GetEncapsulation()->Depth() >= BifConst::Tunnel::max_depth )
			{
			reporter->Weird(c->OrigAddr(), c->RespAddr(), "tunnel_depth");
			// TODO: this should stop this analyzer instance
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
		else
			inner_ip = new IP_Hdr((const struct ip*) ${pdu.packet}.data(), false);
		
		if ( inner_ip != 0)
			connection()->bro_analyzer()->ProtocolConfirmation();
		else
			connection()->bro_analyzer()->ProtocolViolation("ayiya_tunnel_non_ip");
		
		struct pcap_pkthdr fake_hdr;
		fake_hdr.caplen = fake_hdr.len = ${pdu.packet}.length();
		// Not sure what to do with this timestamp.
		//fake_hdr.ts = network_time();
		
		EncapsulatingConn ec(c->OrigAddr(), c->RespAddr(), BifEnum::Tunnel::AYIYA);
		c->GetEncapsulation()->Add(ec);
		
		sessions->DoNextPacket(network_time(), &fake_hdr, inner_ip, ${pdu.packet}.data(), 0, *c->GetEncapsulation());
		
		delete inner_ip;
		return true;
		%}

	};

refine typeattr PDU += &let {
	proc_ayiya = $context.flow.process_ayiya(this);
};
