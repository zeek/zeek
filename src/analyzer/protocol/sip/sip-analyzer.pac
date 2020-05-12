refine flow SIP_Flow += {

	%member{
		int content_length;
		bool build_headers;
		vector<BroVal> headers;
	%}

	%init{
		content_length = 0;
		build_headers = bool(sip_all_headers);
	%}

	function get_content_length(): int
		%{
		return content_length;
		%}

	function proc_sip_request(method: bytestring, uri: bytestring, vers: SIP_Version): bool
		%{
		if ( sip_request )
			{
			BifEvent::enqueue_sip_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						       to_stringval(method), to_stringval(uri),
						       to_stringval(${vers.vers_str}));
			}

		proc_sip_message_begin();

		return true;
		%}

	function proc_sip_reply(vers: SIP_Version, code: int, reason: bytestring): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		if ( sip_reply )
			{
			BifEvent::enqueue_sip_reply(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						     to_stringval(${vers.vers_str}), code, to_stringval(reason));
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
			auto nameval = to_stringval(name);
			nameval->ToUpper();
			BifEvent::enqueue_sip_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
						      is_orig(), std::move(nameval), to_stringval(value));
			}

		if ( build_headers )
			{
			headers.push_back(build_sip_header_val(name, value));
			}

		return true;
		%}

	function build_sip_headers_val(): BroVal
		%{
		static auto mime_header_list = zeek::lookup_type<TableType>("mime_header_list");
		TableVal* t = new TableVal(mime_header_list);

		for ( unsigned int i = 0; i < headers.size(); ++i )
			{ // index starting from 1
			auto index = val_mgr->Count(i + 1);
			t->Assign(index.get(), headers[i]);
			}

		return t;
		%}

	function gen_sip_all_headers(): void
		%{
		if ( sip_all_headers )
			{
			BifEvent::enqueue_sip_all_headers(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
							   is_orig(), {AdoptRef{}, build_sip_headers_val()});
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
		static auto mime_header_rec = zeek::lookup_type<RecordType>("mime_header_rec");
		RecordVal* header_record = new RecordVal(mime_header_rec);
		IntrusivePtr<StringVal> name_val;

		if ( name.length() > 0 )
			{
			// Make it all uppercase.
			name_val = make_intrusive<StringVal>(name.length(), (const char*) name.begin());
			name_val->ToUpper();
			}
		else
			{
			name_val = val_mgr->EmptyString();
			}

		header_record->Assign(0, name_val);
		header_record->Assign(1, to_stringval(value));

		return header_record;
		%}

	function proc_sip_message_begin(): void
		%{
		if ( sip_begin_entity )
			{
			BifEvent::enqueue_sip_begin_entity(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig());
			}
		%}

	function proc_sip_message_done(pdu: SIP_PDU): bool
		%{
		if ( sip_end_entity )
			{
			BifEvent::enqueue_sip_end_entity(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig());
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
