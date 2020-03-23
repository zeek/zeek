
refine flow RDPEUDP_Flow += {
	function proc_rdpeudp_message(msg: RDPEUDP_PDU): bool
		%{
		BifEvent::generate_rdpeudp_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		return true;
		%}
};

refine typeattr RDPEUDP_PDU += &let {
	proc: bool = $context.flow.proc_rdpeudp_message(this);
};
