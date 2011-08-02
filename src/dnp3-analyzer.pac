# $Id:$
#
# This template code contributed by Kristin Stephens.

connection Dnp3_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Dnp3_Flow(true);
	downflow = Dnp3_Flow(false);
};

flow Dnp3_Flow(is_orig: bool) {
	datagram  = Dnp3_PDU(is_orig) withcontext (connection, this);

	function deliver_message(length: uint16): bool
		%{
		if ( ::sample_message )
			{
			BifEvent::generate_sample_message(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), length);
			}

		return true;
		%}
};
