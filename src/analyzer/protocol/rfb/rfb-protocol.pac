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

type RFBProtocolVersion (client: bool) = record {
	header: "RFB ";
	major_ver: bytestring &length=3;
	dot: ".";
	minor_ver: bytestring &length=3;
	pad: uint8;
} &let {
	proc: bool = $context.connection.handle_banners(client, this);
	proc2: bool = $context.flow.proc_rfb_version(client, major_ver, minor_ver);
}

type RFBSecurityTypes = record {
	sectype: uint32;
	possible_challenge: bytestring &restofdata;
} &let {
	proc: bool = $context.connection.handle_security_types(this);
	proc2: bool = $context.flow.proc_security_types(this);
};

type RFBSecurityTypes37 = record {
	count: uint8;
	types: uint8[count];
} &let {
	proc: bool = $context.connection.handle_security_types37(this);
};

type RFBAuthTypeSelected = record {
	type: uint8;
} &let {
	proc: bool = $context.connection.handle_auth_type_selected(this);
	proc2: bool = $context.flow.proc_security_types37(this);
};

type RFBSecurityResult = record {
	result: uint32;
} &let {
	proc: bool = $context.connection.handle_security_result(this);
	proc2: bool = $context.flow.proc_handle_security_result(result);
};

type RFBSecurityResultReason = record {
	len: uint32;
	reason: bytestring &length=len;
};

type RFBVNCAuthenticationRequest = record {
	challenge: bytestring &length=16;
} &let {
	proc: bool = $context.connection.handle_auth_request();
};

type RFBVNCAuthenticationResponse = record {
	response: bytestring &length= 16;
} &let {
	proc: bool = $context.connection.handle_auth_response();
};

type RFBSecurityARDChallenge = record {
	challenge: bytestring &restofdata;
} &let {
	proc: bool = $context.connection.handle_ard_challenge();
}

type RFBSecurityARDResponse = record {
	response: bytestring &restofdata;
} &let {
	proc: bool = $context.connection.handle_ard_response();
}

type RFBClientInit = record {
	shared_flag: uint8;
} &let {
	proc: bool = $context.connection.handle_client_init(this);
	proc2: bool = $context.flow.proc_rfb_share_flag(shared_flag);
}

type RFBServerInit = record {
	width: uint16;
	height: uint16;
	pixel_format: bytestring &length= 16;
	len : uint32;
	name: bytestring &length = len;
} &let {
	proc: bool = $context.connection.handle_server_init(this);
	proc2: bool = $context.flow.proc_handle_server_params(this);
};

type RFB_PDU_request = record {
	request: case state of {
		AWAITING_CLIENT_BANNER -> version: RFBProtocolVersion(true);
		AWAITING_CLIENT_RESPONSE -> response: RFBVNCAuthenticationResponse;
		AWAITING_CLIENT_SHARE_FLAG -> shareflag: RFBClientInit;
		AWAITING_CLIENT_AUTH_TYPE_SELECTED37 -> authtype: RFBAuthTypeSelected;
		AWAITING_CLIENT_ARD_RESPONSE -> ard_response: RFBSecurityARDResponse;
		RFB_MESSAGE -> ignore: bytestring &restofdata &transient;
		default -> data: bytestring &restofdata &transient;
	} &requires(state);
	} &let {
		state: uint8 = $context.connection.get_state(true);
};

type RFB_PDU_response = record {
	request: case rstate of {
		AWAITING_SERVER_BANNER -> version: RFBProtocolVersion(false);
		AWAITING_SERVER_AUTH_TYPES -> auth_types: RFBSecurityTypes;
		AWAITING_SERVER_AUTH_TYPES37 -> auth_types37: RFBSecurityTypes37;
		AWAITING_SERVER_CHALLENGE -> challenge: RFBVNCAuthenticationRequest;
		AWAITING_SERVER_AUTH_RESULT -> authresult : RFBSecurityResult;
		AWAITING_SERVER_ARD_CHALLENGE -> ard_challenge: RFBSecurityARDChallenge;
		AWAITING_SERVER_PARAMS -> serverinit: RFBServerInit;
		RFB_MESSAGE -> ignore: bytestring &restofdata &transient;
		default -> data: bytestring &restofdata &transient;
	} &requires(rstate);
	} &let {
		rstate: uint8 = $context.connection.get_state(false);
};

type RFB_PDU(is_orig: bool) = record {
	payload: case is_orig of {
		true -> request: RFB_PDU_request;
		false -> response: RFB_PDU_response;
	};
} &byteorder = bigendian;
