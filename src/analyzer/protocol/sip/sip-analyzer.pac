refine flow SIP_Flow += {

	%member{
		int content_length;
		bool build_headers;
		vector<BroVal> headers;
	%}

	%init{
		content_length = 0;
		build_headers = (sip_all_headers != 0);
	%}

	function get_content_length(): int
		%{
		return content_length;
		%}

	function proc_sip_request(method: bytestring, uri: bytestring, vers: SIP_Version): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		if ( sip_request )
			{
			BifEvent::generate_sip_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						       bytestring_to_val(method), bytestring_to_val(uri),
						       bytestring_to_val(${vers.vers_str}));
			}

		proc_sip_message_begin();

		return true;
		%}

	function proc_sip_reply(vers: SIP_Version, code: int, reason: bytestring): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		if ( sip_reply )
			{
			BifEvent::generate_sip_reply(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						     bytestring_to_val(${vers.vers_str}), code, bytestring_to_val(reason));
			}

		proc_sip_message_begin();

		return true;
		%}

	function proc_sip_header(name: bytestring, value: bytestring): bool
		%{
		if ( name == "Content-Length" || name == "L" )
			content_length = bytestring_to_int(value, 10);

		if ( sip_header )
			{
			BifEvent::generate_sip_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						      is_orig(), bytestring_to_val(name)->ToUpper(), bytestring_to_val(value));
			}

		if ( build_headers )
			{
			headers.push_back(build_sip_header_val(name, value));
			}

		return true;
		%}

	function build_sip_headers_val(): BroVal
		%{
		TableVal* t = new TableVal(mime_header_list);

		for ( unsigned int i = 0; i < headers.size(); ++i )
			{ // index starting from 1
			Val* index = new Val(i + 1, TYPE_COUNT);
			t->Assign(index, headers[i]);
			Unref(index);
			}

		return t;
		%}

	function gen_sip_all_headers(): void
		%{
		if ( sip_all_headers )
			{
			BifEvent::generate_sip_all_headers(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
							   is_orig(), build_sip_headers_val());
			}

		headers.clear();
		%}

	function proc_sip_end_of_headers(headers: SIP_Headers): bool
		%{
		if ( build_headers )
			{
			gen_sip_all_headers();
			}

		return true;
		%}

	function build_sip_header_val(name: const_bytestring, value: const_bytestring): BroVal
		%{
		RecordVal* header_record = new RecordVal(mime_header_rec);

		StringVal* name_val = 0;
		if ( name.length() > 0 )
			{
			// Make it all uppercase.
			name_val = new StringVal(name.length(), (const char*) name.begin());
			name_val->ToUpper();
			}
		else
			{
			name_val = new StringVal("");
			}

		header_record->Assign(0, name_val);
		header_record->Assign(1, bytestring_to_val(value));

		return header_record;
		%}

	function proc_sip_message_begin(): void
		%{
		if ( sip_begin_entity )
			{
			BifEvent::generate_sip_begin_entity(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig());
			}
		%}

	function proc_sip_message_done(pdu: SIP_PDU): bool
		%{
		if ( sip_end_entity )
			{
			BifEvent::generate_sip_end_entity(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig());
			}

		return true;
		%}

};

refine typeattr SIP_RequestLine += &let {
       proc: bool = $context.flow.proc_sip_request(method, uri, version);
};

refine typeattr SIP_ReplyLine += &let {
       proc: bool = $context.flow.proc_sip_reply(version, status.stat_num, reason);
};

refine typeattr SIP_Header += &let {
       proc: bool = $context.flow.proc_sip_header(name, value);
};

refine typeattr SIP_Headers += &let {
       proc: bool = $context.flow.proc_sip_end_of_headers(this);
};

refine typeattr SIP_PDU += &let {
       proc: bool = $context.flow.proc_sip_message_done(this);
};
