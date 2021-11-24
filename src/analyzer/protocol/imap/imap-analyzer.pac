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
			zeek_analyzer()->AnalyzerConfirmation();

		if ( is_orig && ( command == "capability" || commands == "starttls" ) )
			zeek_analyzer()->AnalyzerConfirmation();

		if ( command == "authenticate" || command == "login" || command == "examine" || command == "create" || command == "list" || command == "fetch" )
			{
			zeek_analyzer()->AnalyzerConfirmation();
			// Handshake has passed the phase where we should see StartTLS. Simply skip from hereon...
			zeek_analyzer()->SetSkip(true);
			return true;
			}

		if ( is_orig && commands == "starttls" )
			{
			if ( !client_starttls_id.empty() )
				zeek_analyzer()->Weird("IMAP: client sent duplicate StartTLS");

			client_starttls_id = tags;
			}

		if ( !is_orig && !client_starttls_id.empty() && tags == client_starttls_id )
			{
			if ( commands == "ok" )
				{
				zeek_analyzer()->StartTLS();

				if ( imap_starttls )
					zeek::BifEvent::enqueue_imap_starttls(zeek_analyzer(), zeek_analyzer()->Conn());
				}
			else
				zeek_analyzer()->Weird("IMAP: server refused StartTLS");
			}

		return true;
		%}

	function proc_server_capability(capabilities: Capability[]): bool
		%{
		if ( ! imap_capabilities )
			return true;

		auto capv = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);

		for ( unsigned int i = 0; i< capabilities->size(); i++ )
			{
			const bytestring& capability = (*capabilities)[i]->cap();
			capv->Assign(i, zeek::make_intrusive<zeek::StringVal>(capability.length(), (const char*)capability.data()));
			}

		zeek::BifEvent::enqueue_imap_capabilities(zeek_analyzer(), zeek_analyzer()->Conn(), std::move(capv));
		return true;
		%}

};

refine typeattr ImapToken += &let {
	proc: bool = $context.connection.proc_imap_token(is_orig, tag, command);
};

refine typeattr ServerCapability += &let {
	proc: bool = $context.connection.proc_server_capability(capabilities);
};
