# client sends RDPEUDP SYN
# server sendds RDPEUDP SYNACK
# client sends TLS or DTLS records wrapped in RDPEUDP or RDPEUDP2, depending on what was negotiated in the handshake
# server sends TLS or DTLS records wrapped in same framing as client
# for now, it'd be great TODO:
#  1. pass the client and server TLS records to the SSL analyzer
#  2. raise an "event rdpeudp_established(c: connection)"

refine flow RDPEUDP_Flow += {
	function proc_rdpeudp_message(msg: RDPEUDP_PDU): bool
		%{
		BifEvent::generate_rdpeudp_syn(
			connection()->bro_analyzer(), 
			connection()->bro_analyzer()->Conn(),
			new StringVal(${msg.data}.length(), (const char*)${msg.data}.begin())
		);
		
		return true;
		%}

};

refine typeattr RDPEUDP_PDU += &let {
	proc: bool = $context.flow.proc_rdpeudp_message(this);
};

