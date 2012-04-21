
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
		connection()->bro_analyzer()->ProtocolConfirmation();
		
		// Not sure what to do here.
		printf("packet: %s\n", ${pdu.packet}.data());
		return true;
		%}

	};

refine typeattr PDU += &let {
	proc_ayiya = $context.flow.process_ayiya(this);
};
