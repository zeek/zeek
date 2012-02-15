%extern{
#include <ctype.h>

// Used by unescape_URI().
extern int is_reserved_URI_char(unsigned char ch);
extern int is_unreserved_URI_char(unsigned char ch);
%}

# Remember to call bytestring::free() on the result.
function to_upper(s: const_bytestring): bytestring
	%{
	char* buf = new char[s.length() + 1];
	const char* sp = (const char*) s.begin();

	for ( int i = 0; i < s.length(); ++i )
		if ( islower(sp[i]) )
			buf[i] = toupper(sp[i]);
		else
			buf[i] = sp[i];

	buf[s.length()] = '\0';

	return bytestring((uint8*) buf, s.length());
	%}

connection HTTP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = HTTP_Flow(true);
	downflow = HTTP_Flow(false);
};

flow HTTP_Flow(is_orig: bool) {
	flowunit = HTTP_PDU(is_orig) withcontext (connection, this);

	# States.
	%member{
		int content_length_;
		DeliveryMode delivery_mode_;
		bytestring end_of_multipart_;

		double msg_start_time_;
		int msg_begin_seq_;
		int msg_header_end_seq_;

		bool build_headers_;
		vector<BroVal> headers_;
	%}

	%init{
		content_length_ = 0;
		delivery_mode_ = UNKNOWN_DELIVERY_MODE;

		msg_start_time_ = 0;
		msg_begin_seq_ = 0;
		msg_header_end_seq_ = -1;

		build_headers_ = (::http_all_headers != 0);
	%}

	%cleanup{
		end_of_multipart_.free();
	%}

	function content_length(): int
		%{
		return content_length_;
		%}

	function delivery_mode(): DeliveryMode
		%{
		return delivery_mode_;
		%}

	function end_of_multipart(): const_bytestring
		%{
		return end_of_multipart_;
		%}

	# Methods.
	function http_request(method: const_bytestring, uri: const_bytestring,
				vers: HTTP_Version): bool
		%{
		if ( ::http_request )
			{
			bytestring unescaped_uri = unescape_uri(uri);
			BifEvent::generate_http_request(connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				bytestring_to_val(method),
				bytestring_to_val(uri),
				bytestring_to_val(unescaped_uri),
				bytestring_to_val(${vers.vers_str}));
			unescaped_uri.free();
			}

		http_message_begin();

		return true;
		%}

	function http_reply(vers: HTTP_Version, code: int,
				reason: const_bytestring): bool
		%{
		if ( ::http_reply )
			{
			BifEvent::generate_http_reply(connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				bytestring_to_val(${vers.vers_str}), code,
				bytestring_to_val(reason));
			}

		http_message_begin();

		return true;
		%}

	function build_http_header_val(name: const_bytestring,
	                               value: const_bytestring): BroVal
		%{
		RecordVal* header_record = new RecordVal(mime_header_rec);

		StringVal* name_val = 0;
		if ( name.length() > 0 )
			{
			// Make it all uppercase.
			name_val = new StringVal(name.length(),
						(const char*) name.begin());
			name_val->ToUpper();
			}
		else
			name_val = new StringVal("");

		header_record->Assign(0, name_val);
		header_record->Assign(1, bytestring_to_val(value));

		return header_record;
		%}

	function extract_boundary(value: const_bytestring): bytestring
		%{
		const char* boundary_prefix = "boundary=";
		const char* boundary_begin = strcasestr(
						(const char*) value.begin(),
						boundary_prefix);

		if ( ! boundary_begin )
			return bytestring();

		boundary_begin += 9;

		const char* boundary_end = strcasestr(boundary_begin, ";");
		if ( ! boundary_end )
			boundary_end = (const char*) value.end();

		return bytestring((const uint8*) boundary_begin,
					(const uint8*) boundary_end);
		%}

	function is_end_of_multipart(line: const_bytestring): bool
		%{
		if ( line.length() < 4 + end_of_multipart_.length() )
			return false;

		int len = end_of_multipart_.length();

		// line =?= "--" end_of_multipart_ "--"
		return ( line[0] == '-' && line[1] == '-' &&
			 line[len + 2] == '-' && line[len + 3] == '-' &&
			 strncmp((const char*) line.begin() + 2,
				(const char*) end_of_multipart_.begin(),
				len) == 0 );
		%}

	function http_header(name_colon: const_bytestring,
	                     value: const_bytestring): bool
		%{
		const_bytestring name(
			name_colon.begin(),
			name_colon.length() > 0 ?
				name_colon.end() - 1 :
				name_colon.end());

		if ( bytestring_casecmp(name, "CONTENT-LENGTH") == 0 )
			{
			content_length_ = bytestring_to_int(value, 10);
			delivery_mode_ = CONTENT_LENGTH;
			}

		else if ( bytestring_casecmp(name, "TRANSFER-ENCODING") == 0 )
			{
			if ( bytestring_caseprefix(value, "CHUNKED") )
				delivery_mode_ = CHUNKED;
			}

		else if ( bytestring_casecmp(name, "CONTENT-TYPE") == 0 )
			{
			if ( bytestring_caseprefix(value, "MULTIPART") )
				{
				end_of_multipart_.free();
				end_of_multipart_ = extract_boundary(value);
				if ( end_of_multipart_.length() > 0 )
					delivery_mode_ = MULTIPART;
				}
			}

		if ( ::http_header )
			{
			BifEvent::generate_http_header(connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				bytestring_to_val(name)->ToUpper(),
				bytestring_to_val(value));
			}

		if ( build_headers_ )
			headers_.push_back(build_http_header_val(name, value));

		return true;
		%}

	function build_http_headers_val(): BroVal
		%{
		TableVal* t = new TableVal(mime_header_list);

		for ( unsigned int i = 0; i < headers_.size(); ++i )
			{ // index starting from 1
			Val* index = new Val(i + 1, TYPE_COUNT);
			t->Assign(index, headers_[i]);
			Unref(index);
			}

		return t;
		%}

	function gen_http_all_headers(): void
		%{
		if ( ::http_all_headers )
			{
			BifEvent::generate_http_all_headers(connection()->bro_analyzer(),
						connection()->bro_analyzer()->Conn(),
						is_orig(),
						build_http_headers_val());
			}

		headers_.clear();
		%}

	function http_end_of_headers(headers: HTTP_Headers): bool
		%{
		if ( delivery_mode_ != CHUNKED && build_headers_ )
			gen_http_all_headers();

		// Check if this is the first set of headers
		// (i.e. not headers after chunks).
		if ( msg_header_end_seq_ == -1 )
			msg_header_end_seq_ = flow_buffer_->data_seq();

		return true;
		%}

	function http_message_begin(): void
		%{
		msg_start_time_ = network_time();
		if ( ::http_begin_entity )
			{
			BifEvent::generate_http_begin_entity(connection()->bro_analyzer(),
							connection()->bro_analyzer()->Conn(), is_orig());
			}
		%}

	function build_http_message_stat(): BroVal
		%{
		int msg_header_length = msg_header_end_seq_ - msg_begin_seq_;
		int msg_body_length =
			flow_buffer_->data_seq() - msg_header_end_seq_;

		bool msg_interrupted = false;

		RecordVal* stat = new RecordVal(http_message_stat);
		int field = 0;
		stat->Assign(field++, new Val(msg_start_time_, TYPE_TIME));
		stat->Assign(field++, new Val(msg_interrupted, TYPE_BOOL));
		stat->Assign(field++, new StringVal(""));
		stat->Assign(field++, new Val(msg_body_length, TYPE_COUNT));
		stat->Assign(field++, new Val(0, TYPE_COUNT));
		stat->Assign(field++, new Val(msg_header_length, TYPE_COUNT));

		return stat;
		%}

	function http_message_done(pdu: HTTP_PDU): bool
		%{
		if ( ! headers_.empty() )
			gen_http_all_headers();

		if ( ::http_end_entity )
			{
			BifEvent::generate_http_end_entity(connection()->bro_analyzer(),
							connection()->bro_analyzer()->Conn(), is_orig());
			}

		if ( ::http_message_done )
			{
			BifEvent::generate_http_message_done(connection()->bro_analyzer(),
					connection()->bro_analyzer()->Conn(),
					is_orig(), build_http_message_stat());
			}

		end_of_multipart_.free();

		// Initialize for next message.
		msg_begin_seq_ = flow_buffer_->data_seq();
		msg_header_end_seq_ = -1;

		return true;
		%}

	# Remember to call bytestring::free() on the result
	function unescape_uri(uri: const_bytestring): bytestring
		%{
		const u_char* line = uri.begin();
		const u_char* line_end = uri.end();
		BroAnalyzer a = connection()->bro_analyzer();

		// ### Copied from HTTP.cc
		byte_vec decoded_URI = new u_char[line_end - line + 1];
		byte_vec URI_p = decoded_URI;

		// An 'unescaped_special_char' here means a character that
		// *should* be escaped, but isn't in the URI.  A control
		// character that appears directly in the URI would be an
		// example.  The RFC implies that if we do not unescape the
		// URI that we see in the trace, every character should be a
		// printable one -- either reserved or unreserved (or '%').
		//
		// Counting the number of unescaped characters and generating
		// a weird event on URI's with unescaped characters (which
		// are rare) will let us locate strange-looking URI's in the
		// trace -- those URI's are often interesting.

		int unescaped_special_char = 0;

		while ( line < line_end )
			{
			if ( *line == '%' )
				{
				++line;

				if ( line == line_end )
					{
					// How to deal with % at end of line?
					// *URI_p++ = '%';
					if ( a )
						a->Weird("illegal_%_at_end_of_URI");
					break;
					}

				else if ( *line == '%' )
					{
					// Double '%' might be either due to
					// software bug, or, more likely, an
					// evasion (e.g., used by Nimda).
					// *URI_p++ = '%';
					if ( a )
						a->Weird("double_%_in_URI");
					--line;	// ignore the first '%'
					}

				else if ( isxdigit(line[0]) && isxdigit(line[1]) )
					{
					*URI_p++ = (decode_hex(line[0]) << 4) +
						   decode_hex(line[1]);
					++line; // place line at last hex digit
					}

				else
					{
					if ( a )
						a->Weird("unescaped_%_in_URI");
					*URI_p++ = '%';	// put back initial '%'
					// Take char. without interpretation..
					*URI_p++ = *line;
					}
				}

			else
				{
				if ( ! is_reserved_URI_char(*line) &&
				     ! is_unreserved_URI_char(*line) )
					// Count these up as a way to compress
					// the corresponding Weird event to a
					// single instance.
					++unescaped_special_char;
				*URI_p++ = *line;
				}

			++line;
			}

		URI_p[0] = 0;

		if ( unescaped_special_char && a )
			a->Weird("unescaped_special_URI_char");

		return bytestring(decoded_URI, URI_p - decoded_URI);
		%}
};

refine typeattr HTTP_RequestLine += &let {
	process_request: bool =
		$context.flow.http_request(method, uri, version);
};

refine typeattr HTTP_ReplyLine += &let {
	process_reply: bool =
		$context.flow.http_reply(version, status.stat_num, reason);
};

refine typeattr HTTP_Header += &let {
	process_header: bool =
		$context.flow.http_header(name, value);
};

refine typeattr HTTP_Headers += &let {
	process_end_of_headers: bool =
		$context.flow.http_end_of_headers(this);
};

refine typeattr HTTP_PDU += &let {
	process_message: bool =
		$context.flow.http_message_done(this);
};
