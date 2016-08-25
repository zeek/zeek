refine flow RFB_Flow += {
	function proc_rfb_message(msg: RFB_PDU): bool
		%{
		BifEvent::generate_rfb_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		return true;
		%}

	function proc_rfb_version(client: bool, major: bytestring, minor: bytestring) : bool
		%{
		if (client)
			{
			BifEvent::generate_rfb_client_version(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), bytestring_to_val(major), bytestring_to_val(minor));

			connection()->bro_analyzer()->ProtocolConfirmation();
			}
			else
			{
			BifEvent::generate_rfb_server_version(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), bytestring_to_val(major), bytestring_to_val(minor));
			}
		return true;
		%}

	function proc_rfb_share_flag(shared: bool) : bool
		%{
		BifEvent::generate_rfb_share_flag(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), shared);
		return true;
		%}

	function proc_security_types(msg: RFBSecurityTypes) : bool
		%{
		BifEvent::generate_rfb_authentication_type(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${msg.sectype});
		return true;
		%}

	function proc_security_types37(msg: RFBAuthTypeSelected) : bool
		%{
		BifEvent::generate_rfb_authentication_type(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${msg.type});
		return true;
		%}

	function proc_handle_server_params(msg:RFBServerInit) : bool
		%{
		BifEvent::generate_rfb_server_parameters(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), bytestring_to_val(${msg.name}), ${msg.width}, ${msg.height});
		return true;
		%}

	function proc_handle_security_result(result : uint32) : bool
		%{
		BifEvent::generate_rfb_auth_result(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), result);
		return true;
		%}
};

refine connection RFB_Conn += {
	%member{
		enum states {
			AWAITING_SERVER_BANNER = 0,
			AWAITING_CLIENT_BANNER = 1,
			AWAITING_SERVER_AUTH_TYPES = 2,
			AWAITING_SERVER_CHALLENGE = 3,
			AWAITING_CLIENT_RESPONSE = 4,
			AWAITING_SERVER_AUTH_RESULT = 5,
			AWAITING_CLIENT_SHARE_FLAG = 6,
			AWAITING_SERVER_PARAMS = 7,
			AWAITING_CLIENT_AUTH_METHOD = 8,
			AWAITING_SERVER_ARD_CHALLENGE = 9,
			AWAITING_CLIENT_ARD_RESPONSE = 10,
			AWAITING_SERVER_AUTH_TYPES37 = 11,
			AWAITING_CLIENT_AUTH_TYPE_SELECTED37 = 12,
			RFB_MESSAGE = 13
		};
	%}

	function get_state(client: bool) : int
		%{
		return state;
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
				state = AWAITING_SERVER_AUTH_TYPES37;
			else
				state = AWAITING_SERVER_AUTH_TYPES;
			}
			else
				state = AWAITING_CLIENT_BANNER;

		return true;
		%}

	function handle_ard_challenge() : bool
		%{
		state = AWAITING_CLIENT_ARD_RESPONSE;
		return true;
		%}

	function handle_ard_response() : bool
		%{
		state = AWAITING_SERVER_AUTH_RESULT;
		return true;
		%}

	function handle_auth_request() : bool
		%{
		state = AWAITING_CLIENT_RESPONSE;
		return true;
		%}

	function handle_auth_response() : bool
		%{
		state = AWAITING_SERVER_AUTH_RESULT;
		return true;
		%}

	function handle_security_result(msg: RFBSecurityResult) : bool
		%{
		if ( ${msg.result} == 0 )
			{
			state = AWAITING_CLIENT_SHARE_FLAG;
			}
		return true;
		%}

	function handle_client_init(msg: RFBClientInit) : bool
		%{
		state = AWAITING_SERVER_PARAMS;
		return true;
		%}

	function handle_server_init(msg: RFBServerInit) : bool
		%{
		state = RFB_MESSAGE;
		return true;
		%}

	function handle_security_types(msg: RFBSecurityTypes): bool
		%{
		if ( msg->sectype() == 0 )
			{ // No auth
			state = AWAITING_CLIENT_SHARE_FLAG;
			return true;
			}

		if ( msg->sectype() == 2 )
			{ // VNC
			if ( ${msg.possible_challenge}.length() == 16 )
				// Challenge was already sent with this message
				state = AWAITING_CLIENT_RESPONSE;
			else
				state = AWAITING_SERVER_CHALLENGE;
			}
		return true;
		%}

	function handle_security_types37(msg: RFBSecurityTypes37): bool
		%{
		if ( ${msg.count} == 0 )
			{ // No auth
			state = AWAITING_CLIENT_SHARE_FLAG;
			return true;
			}
		state = AWAITING_CLIENT_AUTH_TYPE_SELECTED37;
		return true;
		%}

	function handle_auth_type_selected(msg: RFBAuthTypeSelected): bool
		%{
		if ( ${msg.type} == 30 )
			{ // Apple Remote Desktop
				state = AWAITING_SERVER_ARD_CHALLENGE;
				return true;
			}

		if ( ${msg.type} == 1 )
			{
				if ( version > 7 )
					state = AWAITING_SERVER_AUTH_RESULT;
				else
					state = AWAITING_CLIENT_SHARE_FLAG;
			}
		else
			state = AWAITING_SERVER_CHALLENGE;

		return true;
		%}

	%member{
		uint8 state = AWAITING_SERVER_BANNER;
		int version = 0;
	%}
};

refine typeattr RFB_PDU += &let {
	proc: bool = $context.flow.proc_rfb_message(this);
};
