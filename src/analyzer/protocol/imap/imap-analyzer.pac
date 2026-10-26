%extern{
#include <algorithm>

#include "zeek/analyzer/protocol/imap/consts.bif.h"
%}

refine connection IMAP_Conn += {

	%member{
		string client_starttls_id;
		zeek::VectorValPtr capabilities;
		uint64_t total_capabilities;
		bool capability_had_nl;
	%}

	%init{
		total_capabilities = 0;
		capability_had_nl = false;
	%}

	function proc_imap_token(is_orig: bool, tag: bytestring, command: bytestring): bool
		%{
		string commands = std_str(command);
		std::ranges::transform(commands, commands.begin(), ::tolower);

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

	function proc_one_capability(cap: Capability): bool
		%{
		++total_capabilities;
		assert(!capability_had_nl);

		if ( ${cap.nl}.length() > 0 )
			capability_had_nl = true;

		// If event not implemented, short-circuit.
		if ( ! imap_capabilities )
			return true;

		if ( ! capabilities )
			capabilities = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);

		if ( zeek::BifConst::IMAP::max_capabilities > 0 && capabilities->Size() >= zeek::BifConst::IMAP::max_capabilities )
			return true;

		capabilities->Append(zeek::make_intrusive<zeek::StringVal>(${cap.cap}.length(), reinterpret_cast<const char*>(${cap.cap}.data())));
		return true;
		%}

	# Returns true once a capability with a trailing \r\n has been observed
	# during proc_one_capability().
	function capabilities_line_done(): bool
		%{
		return capability_had_nl;
		%}

	function proc_server_capability(): bool
		%{
		// Raise a weird here if max_capabilities was reached and short-circuited above
		// for anything that comes additionally.
		if ( zeek::BifConst::IMAP::max_capabilities > 0 && total_capabilities > zeek::BifConst::IMAP::max_capabilities )
			zeek_analyzer()->LimitReachedWeird("imap_max_capabilities_reached", total_capabilities, zeek::BifConst::IMAP::max_capabilities);

		if ( imap_capabilities )
			zeek::BifEvent::enqueue_imap_capabilities(zeek_analyzer(), zeek_analyzer()->Conn(), std::move(capabilities));

		capability_had_nl = false;
		total_capabilities = 0;
		capabilities.reset();
		return true;
		%}

};

refine typeattr ImapToken += &let {
	proc: bool = $context.connection.proc_imap_token(is_orig, tag, command);
};

refine typeattr Capability += &let {
	proc: bool = $context.connection.proc_one_capability(this);
};

refine typeattr ServerCapability += &let {
	proc: bool = $context.connection.proc_server_capability();
};
