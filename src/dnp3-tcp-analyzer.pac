# $Id:$
#
# This template code contributed by Kristin Stephens.

connection Dnp3TCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Dnp3TCP_Flow(true);
	downflow = Dnp3TCP_Flow(false);
};

flow Dnp3TCP_Flow(is_orig: bool) {
	flowunit = Sample_Message withcontext (connection, this);

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
