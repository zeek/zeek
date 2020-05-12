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
				{
				bro_analyzer()->StartTLS();

				if ( imap_starttls )
					BifEvent::enqueue_imap_starttls(bro_analyzer(), bro_analyzer()->Conn());
				}
			else
				reporter->Weird(bro_analyzer()->Conn(), "IMAP: server refused StartTLS");
			}

		return true;
		%}

	function proc_server_capability(capabilities: Capability[]): bool
		%{
		if ( ! imap_capabilities )
			return true;

		auto capv = make_intrusive<VectorVal>(zeek::vars::string_vec);

		for ( unsigned int i = 0; i< capabilities->size(); i++ )
			{
			const bytestring& capability = (*capabilities)[i]->cap();
			capv->Assign(i, make_intrusive<StringVal>(capability.length(), (const char*)capability.data()));
			}

		BifEvent::enqueue_imap_capabilities(bro_analyzer(), bro_analyzer()->Conn(), std::move(capv));
		return true;
		%}

};

refine typeattr ImapToken += &let {
	proc: bool = $context.connection.proc_imap_token(is_orig, tag, command);
};

refine typeattr ServerCapability += &let {
	proc: bool = $context.connection.proc_server_capability(capabilities);
};
