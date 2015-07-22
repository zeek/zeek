refine connection IMAP_Conn += {

	%member{
	string client_starttls_id;
	%}

	%init{
	%}

	function proc_imap_token(is_orig: bool, tag: bytestring, command: bytestring): bool
		%{
		string commands = std_str(command);
		std::transform(commands.begin(), commands.end(), commands.begin(), ::tolower);

		string tags = std_str(tag);

		//printf("imap %s %s\n", commands.c_str(), tags.c_str());

		if ( !is_orig && tags == "*" && commands == "ok" )
			bro_analyzer()->ProtocolConfirmation();

		if ( is_orig && ( command == "capability" || commands == "starttls" ) )
			bro_analyzer()->ProtocolConfirmation();

		if ( command == "authenticate" || command == "login" || command == "examine" || command == "create" || command == "list" || command == "fetch" )
			{
			bro_analyzer()->ProtocolConfirmation();
			// Handshake has passed the phase where we should see StartTLS. Simply skip from hereon...
			bro_analyzer()->SetSkip(true);
			return true;
			}

		if ( is_orig && commands == "starttls" )
			{
			if ( !client_starttls_id.empty() )
				reporter->Weird(bro_analyzer()->Conn(), "IMAP: client sent duplicate StartTLS");

			client_starttls_id = tags;
			}

		if ( !is_orig && !client_starttls_id.empty() && tags == client_starttls_id )
			{
			if ( commands == "ok" )
				bro_analyzer()->StartTLS();
			else
				reporter->Weird(bro_analyzer()->Conn(), "IMAP: server refused StartTLS");
			}

		return true;
		%}

};

refine typeattr IMAP_TOKEN += &let {
       proc: bool = $context.connection.proc_imap_token(is_orig, tag, command);
};

