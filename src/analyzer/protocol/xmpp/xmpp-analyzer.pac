refine connection XMPP_Conn += {

	%member{
	bool client_starttls;
	%}

	%init{
	client_starttls = false;
	%}

	function proc_xmpp_token(is_orig: bool, name: bytestring, rest: bytestring): bool
		%{
		string token = std_str(name);

		if ( is_orig && token == "stream:stream" )
			// Yup, looks like xmpp...
			bro_analyzer()->ProtocolConfirmation();

		if ( token == "success" || token == "message" || token == "db:result"
		     || token == "db:verify" || token == "presence" )
			// Handshake has passed the phase where we should see StartTLS. Simply skip from hereon...
			bro_analyzer()->SetSkip(true);

		if ( is_orig && token == "starttls" )
			client_starttls = true;

		if ( !is_orig && token == "proceed" && client_starttls )
			{
			bro_analyzer()->StartTLS();
			BifEvent::generate_xmpp_starttls(bro_analyzer(), bro_analyzer()->Conn());
			}
		else if ( !is_orig && token == "proceed" )
			reporter->Weird(bro_analyzer()->Conn(), "XMPP: proceed without starttls");

		//printf("Processed: %d %s %s \n", is_orig, c_str(name), c_str(rest));

		return true;
		%}

};

refine typeattr XMPP_TOKEN += &let {
	proc: bool = $context.connection.proc_xmpp_token(is_orig, name, rest);
};

