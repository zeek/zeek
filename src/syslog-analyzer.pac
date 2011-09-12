
refine flow Syslog_Flow += {

	function process_syslog_message(m: Syslog_Message): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		
		int cut_end = 0;
		bool reached_noncutable_char = false;
		while ( ! reached_noncutable_char )
			{
			const u_char last_char = *(${m.msg}.begin()-1 + ${m.msg}.length()-cut_end);
			// Remove all of the characters that tend to accumulate at the 
			// of lines in syslog messages.
			if ( last_char == 0x0a || 
			     last_char == 0x00 ) 
				++cut_end;
			else
				reached_noncutable_char = true;
			}

		BifEvent::generate_syslog_message(connection()->bro_analyzer(),
		                                  connection()->bro_analyzer()->Conn(),
		                                  ${m.PRI.facility},
		                                  ${m.PRI.severity},
		                                  new StringVal(${m.msg}.length()-cut_end, (const char*) ${m.msg}.begin())
		                                  );
		return true;
		%}

};

refine typeattr Syslog_Message += &let {
	proc_syslog_message = $context.flow.process_syslog_message(this);
};
