
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
		const Encapsulation* e = c->GetEncapsulation();
		
		if ( e && e->Depth() >= BifConst::Tunnel::max_depth )
			{
			reporter->Weird(c, "tunnel_depth");
			return false;
			}
		
		if ( ${pdu.op} != 1 )
			{
			// 1 is the "forward" command.
			return false;
			}
		
		if ( ${pdu.next_header} != IPPROTO_IPV6 &&
		     ${pdu.next_header} != IPPROTO_IPV4 )
			{
			reporter->Weird(c, "ayiya_tunnel_non_ip");
			return false;
			}
		
		connection()->bro_analyzer()->ProtocolConfirmation();
		
		Encapsulation* outer = new Encapsulation(e);
		EncapsulatingConn ec(c, BifEnum::Tunnel::AYIYA);
		outer->Add(ec);
		
		sessions->DoNextInnerPacket(network_time(), 0, ${pdu.packet}.length(),
		                            ${pdu.packet}.data(), ${pdu.next_header},
		                            outer);
		
		delete outer;
		return true;
		%}

	};

refine typeattr PDU += &let {
	proc_ayiya = $context.flow.process_ayiya(this);
};
