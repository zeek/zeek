refine flow RFB_Flow += {
	function proc_rfb_version(client: bool, major: bytestring, minor: bytestring) : bool
		%{
		if ( client )
			{
			if ( rfb_client_version )
				zeek::BifEvent::enqueue_rfb_client_version(connection()->zeek_analyzer(),
				                                     connection()->zeek_analyzer()->Conn(),
				                                     to_stringval(major),
				                                     to_stringval(minor));

			connection()->zeek_analyzer()->AnalyzerConfirmation();
			}
		else
			{
			if ( rfb_server_version )
				zeek::BifEvent::enqueue_rfb_server_version(connection()->zeek_analyzer(),
				                                     connection()->zeek_analyzer()->Conn(),
				                                     to_stringval(major),
				                                     to_stringval(minor));
			}

		return true;
		%}

	function proc_rfb_share_flag(shared: bool) : bool
		%{
		if ( rfb_share_flag )
			zeek::BifEvent::enqueue_rfb_share_flag(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), shared);
		return true;
		%}

	function proc_security_types(msg: RFBSecurityType) : bool
		%{
		if ( rfb_authentication_type )
			zeek::BifEvent::enqueue_rfb_authentication_type(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), ${msg.sectype});
		return true;
		%}

	function proc_security_types37(msg: RFBAuthTypeSelected) : bool
		%{
		if ( rfb_authentication_type )
			zeek::BifEvent::enqueue_rfb_authentication_type(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), ${msg.type});
		return true;
		%}

	function proc_handle_server_params(msg:RFBServerInit) : bool
		%{
		if ( rfb_server_parameters )
			{
			auto vec_ptr = ${msg.name};
			auto name_ptr = &((*vec_ptr)[0]);
			zeek::BifEvent::enqueue_rfb_server_parameters(
			    connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
			    zeek::make_intrusive<zeek::StringVal>(${msg.name}->size(), (const char*)name_ptr),
			    ${msg.width},
			    ${msg.height});
			}
		return true;
		%}

	function proc_handle_security_result(result : uint32) : bool
		%{
		if ( rfb_auth_result )
			zeek::BifEvent::enqueue_rfb_auth_result(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), result);
		return true;
		%}
};

refine connection RFB_Conn += {
	%member{
		enum ServerState {
			SERVER_VERSION            =  0,
			SERVER_AUTH_TYPE          =  1,
			SERVER_AUTH_TYPE37        =  2,
			SERVER_AUTH_FAILURE       =  3,
			SERVER_AUTH_VNC_CHALLENGE =  4,
			SERVER_AUTH_ARD_CHALLENGE =  5,
			SERVER_AUTH_RESULT        =  6,
			SERVER_INIT               =  7,
			SERVER_MESSAGE_TYPE       =  8,
			SERVER_MESSAGE            =  9,
			SERVER_WAIT               = 99,
			SERVER_INVALID            =100,
		};

		enum ClientState {
			CLIENT_VERSION           =  0,
			CLIENT_AUTH_SELECTION    =  1,
			CLIENT_AUTH_VNC_RESPONSE =  2,
			CLIENT_AUTH_ARD_RESPONSE =  3,
			CLIENT_INIT              =  4,
			CLIENT_MESSAGE_TYPE      =  5,
			CLIENT_MESSAGE           =  6,
			CLIENT_WAIT              = 99,
			CLIENT_INVALID           =100,
		};

		int version = 0;
		uint8 client_state = CLIENT_VERSION;
		uint8 server_state = SERVER_VERSION;
		uint16 ard_key_length = 0;
		uint8 next_client_msg = 0;
		uint8 next_server_msg = 0;
		uint8 bytes_per_pixel = 0;
		bool saw_full_handshake = false;
	%}

	function saw_handshake() : bool
		%{
		return saw_full_handshake;
		%}

	function get_ard_key_length() : uint16
		%{
		return ard_key_length;
		%}

	function get_state(client: bool) : int
		%{
		return client ? client_state : server_state;
		%}

	function get_next_msg_type(client: bool) : uint8
		%{
		return client ? next_client_msg : next_server_msg;
		%}

	function get_bytes_per_pixel() : uint8
		%{
		return bytes_per_pixel;
		%}

	function handle_banners(client: bool, msg: RFBProtocolVersion) : bool
		%{
		if ( client )
			{
			// Set protocol version on client's version
			int minor_version = bytestring_to_int(${msg.minor_ver},10);
			version = minor_version;

			// Apple specifies minor version "889" but talks v37
			if ( minor_version >= 7 )
				{
				server_state = SERVER_AUTH_TYPE37;
				client_state = CLIENT_AUTH_SELECTION;
				}
			else
				{
				server_state = SERVER_AUTH_TYPE;
				client_state = CLIENT_WAIT;
				}

			}
		else
			server_state = SERVER_WAIT;

		return true;
		%}

	function handle_security_type(msg: RFBSecurityType): bool
		%{
		if ( msg->sectype() == 0 )
			{
			// Invalid / failure.
			server_state = SERVER_AUTH_FAILURE;
			client_state = CLIENT_INIT;
			}
		else if ( msg->sectype() == 1 )
			{
			// No auth.
			server_state = SERVER_INIT;
			client_state = CLIENT_INIT;
			}
		else if ( msg->sectype() == 2 )
			{
			// VNC auth.
			server_state = SERVER_AUTH_VNC_CHALLENGE;
			client_state = CLIENT_AUTH_VNC_RESPONSE;
			}
		else
			{
			// Shouldn't be a possible.
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid RFB security type %u", msg->sectype()));
			}

		return true;
		%}

	function handle_fail_reason_string(msg: RFBFailReasonString): bool
		%{
		// Connection failed, server should close, but maybe see if it
		// proceeds anyway.
		server_state = SERVER_INIT;
		return true;
		%}

	function handle_security_types37(msg: RFBSecurityTypes37): bool
		%{
		if ( ${msg.count} == 0 )
			{
			server_state = SERVER_AUTH_FAILURE;
			}
		else
			{
			server_state = SERVER_WAIT;
			}

		return true;
		%}

	function handle_auth_type_selected(msg: RFBAuthTypeSelected): bool
		%{
		if ( ${msg.type} == 1 )
			{
			if ( version > 7 )
				server_state = SERVER_AUTH_RESULT;
			else
				server_state = SERVER_INIT;

			client_state = CLIENT_INIT;
			}
		else if ( ${msg.type} == 2 )
			{
			server_state = SERVER_AUTH_VNC_CHALLENGE;
			client_state = CLIENT_AUTH_VNC_RESPONSE;
			}
		else if ( ${msg.type} == 30 )
			{
			// Apple Remote Desktop
			server_state = SERVER_AUTH_ARD_CHALLENGE;
			//client_state = CLIENT_AUTH_ARD_RESPONSE;
			// need to wait for the key length to be set by server
			client_state = CLIENT_WAIT;
			}
		else
			{
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("unknown RFB auth selection: %u", ${msg.type}));
			}

		return true;
		%}

	function handle_ard_challenge(msg: RFBSecurityARDChallenge) : bool
		%{
		ard_key_length = ${msg.key_length};
		server_state = SERVER_AUTH_RESULT;
		client_state = CLIENT_AUTH_ARD_RESPONSE;
		return true;
		%}

	function handle_ard_response() : bool
		%{
		client_state = CLIENT_INIT;
		return true;
		%}

	function handle_auth_request() : bool
		%{
		server_state = SERVER_AUTH_RESULT;
		client_state = CLIENT_AUTH_VNC_RESPONSE;
		return true;
		%}

	function handle_auth_response() : bool
		%{
		client_state = CLIENT_INIT;
		return true;
		%}

	function handle_security_result(msg: RFBSecurityResult) : bool
		%{
		if ( ${msg.result} == 0 )
			// OK
			server_state = SERVER_INIT;
		else if ( ${msg.result} == 1 )
			// Failed
			server_state = SERVER_AUTH_FAILURE;
		else
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid RFB auth result: %u", ${msg.result}));

		return true;
		%}

	function handle_client_init(msg: RFBClientInit) : bool
		%{
		client_state = CLIENT_MESSAGE_TYPE;
		return true;
		%}

	function handle_server_init(msg: RFBServerInit) : bool
		%{
		auto bits_per_pixel = (*${msg.pixel_format})[0];
		bytes_per_pixel = bits_per_pixel / 8;
		server_state = SERVER_MESSAGE_TYPE;
		saw_full_handshake = true;
		return true;
		%}

	function handle_wait_data(client: bool) : bool
		%{
		if ( client )
			client_state = CLIENT_INVALID;
		else
			server_state = SERVER_INVALID;

		return true;
		%}

	function handle_invalid_data(client: bool) : bool
		%{
		throw binpac::Exception(zeek::util::fmt("invalid data from RFB %s", client ? "client" : "server"));
		return true;
		%}

	function handle_client_message_type(type: uint8) : bool
		%{
		next_client_msg = type;
		client_state = CLIENT_MESSAGE;
		return true;
		%}

	function handle_client_message(type: uint8) : bool
		%{
		client_state = CLIENT_MESSAGE_TYPE;
		return true;
		%}

	function handle_server_message_type(type: uint8) : bool
		%{
		next_server_msg = type;
		server_state = SERVER_MESSAGE;
		return true;
		%}

	function handle_server_message(type: uint8) : bool
		%{
		server_state = SERVER_MESSAGE_TYPE;
		return true;
		%}

	function handle_client_set_pixel_format(msg: ClientSetPixelFormat) : bool
		%{
		auto bits_per_pixel = (*${msg.pixel_format})[0];
		bytes_per_pixel = bits_per_pixel / 8;
		return true;
		%}

	function handle_client_set_encodings(msg: ClientSetEncodings) : bool
		%{
		return true;
		%}

	function handle_client_framebuffer_update_request(msg: ClientFramebufferUpdateRequest) : bool
		%{
		return true;
		%}

	function handle_client_key_event(msg: ClientKeyEvent) : bool
		%{
		return true;
		%}

	function handle_client_pointer_event(msg: ClientPointerEvent) : bool
		%{
		return true;
		%}

	function handle_client_cut_text(msg: ClientCutText) : bool
		%{
		return true;
		%}
};
