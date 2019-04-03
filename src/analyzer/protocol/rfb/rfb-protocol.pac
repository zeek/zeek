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

# The protocol specifies some 32-bit variable-length data fields with the
# length derived from packet data.
# This value enforces sane length values to help prevent excessive buffering.
let MAX_DATA_LENGTH: uint32 = 65536;

type RFBProtocolVersion (client: bool) = record {
	header: "RFB ";
	major_ver: bytestring &length=3;
	dot: ".";
	minor_ver: bytestring &length=3;
	pad: uint8;
} &let {
	proc: bool = $context.connection.handle_banners(client, this);
	proc2: bool = $context.flow.proc_rfb_version(client, major_ver, minor_ver);
} &length=12;

type RFBFailReasonString = record {
	len: uint32 &enforce(len < MAX_DATA_LENGTH);
	str: bytestring &length=len;
} &let {
	proc: bool = $context.connection.handle_fail_reason_string(this);
} &length=(4 + len);

type RFBSecurityType = record {
	sectype: uint32;
} &let {
	proc: bool = $context.connection.handle_security_type(this);
	proc2: bool = $context.flow.proc_security_types(this);
} &length=4;

type RFBSecurityTypes37 = record {
	count: uint8;
	types: uint8[count];
} &let {
	proc: bool = $context.connection.handle_security_types37(this);
} &length=(count + 1);

type RFBAuthTypeSelected = record {
	type: uint8;
} &let {
	proc: bool = $context.connection.handle_auth_type_selected(this);
	proc2: bool = $context.flow.proc_security_types37(this);
} &length=1;

type RFBSecurityResult = record {
	result: uint32;
} &let {
	proc: bool = $context.connection.handle_security_result(this);
	proc2: bool = $context.flow.proc_handle_security_result(result);
} &length=4;

type RFBVNCAuthenticationRequest = record {
	challenge: bytestring &length=16;
} &let {
	proc: bool = $context.connection.handle_auth_request();
} &length=16;

type RFBVNCAuthenticationResponse = record {
	response: bytestring &length= 16;
} &let {
	proc: bool = $context.connection.handle_auth_response();
} &length=16;

type RFBSecurityARDChallenge = record {
	# TODO: Not sure if this all is complete/accurate, could not find the spec.
	generator: uint16;
	key_length: uint16;
	prime_mod: bytestring &length=key_length;
	publickey: bytestring &length=key_length;
} &let {
	proc: bool = $context.connection.handle_ard_challenge(this);
} &length=(4 + (2 * key_length));

type RFBSecurityARDResponse = record {
	publickey: bytestring &length=$context.connection.get_ard_key_length();
	creds: bytestring &length=$context.connection.get_ard_key_length();
} &let {
	proc: bool = $context.connection.handle_ard_response();
} &length=(2 * $context.connection.get_ard_key_length());

type RFBClientInit = record {
	shared_flag: uint8;
} &let {
	proc: bool = $context.connection.handle_client_init(this);
	proc2: bool = $context.flow.proc_rfb_share_flag(shared_flag);
} &length=1;

type RFBServerInit = record {
	width: uint16;
	height: uint16;
	pixel_format: uint8[16];
	len: uint32 &enforce(len < MAX_DATA_LENGTH);
	name: uint8[len];
} &let {
	proc: bool = $context.connection.handle_server_init(this);
	proc2: bool = $context.flow.proc_handle_server_params(this);
} &length=24 + len;

type InvalidData(orig: bool) = record {
	invalid: uint8;
} &let {
	proc: bool = $context.connection.handle_invalid_data(orig);
} &length=1;

type WaitData(orig: bool) = record {
	nothing: bytestring &length = 0;
} &let {
	proc: bool = $context.connection.handle_wait_data(orig);
} &length=0;

type ClientMessageType = record {
	type: uint8;
} &let {
	proc: bool = $context.connection.handle_client_message_type(type);
} &length=1;

type ClientMessage(type: uint8) = case type of {
	0 -> set_pixel_format: ClientSetPixelFormat;
	2 -> set_encodings: ClientSetEncodings;
	3 -> framebuffer_update_request: ClientFramebufferUpdateRequest;
	4 -> key_event: ClientKeyEvent;
	5 -> pointer_event: ClientPointerEvent;
	6 -> cut_text: ClientCutText;
} &let {
	proc: bool = $context.connection.handle_client_message(type);
};

type ClientSetPixelFormat = record {
	pad: uint8[3];
	pixel_format: uint8[16];
} &let {
	proc: bool = $context.connection.handle_client_set_pixel_format(this);
} &length=19;

type ClientSetEncodings = record {
	pad: uint8;
	num_encodings: uint16;
	encodings: uint32[num_encodings];
} &let {
	proc: bool = $context.connection.handle_client_set_encodings(this);
} &length=3 + (4 * num_encodings);

type ClientFramebufferUpdateRequest = record {
	incremental: uint8;
	xpos: uint16;
	ypos: uint16;
	width: uint16;
	height: uint16;
} &let {
	proc: bool = $context.connection.handle_client_framebuffer_update_request(this);
} &length=9;

type ClientKeyEvent = record {
	down_flag: uint8;
	pad: uint16;
	key: uint32;
} &let {
	proc: bool = $context.connection.handle_client_key_event(this);
} &length=7;

type ClientPointerEvent = record {
	button_mask: uint8;
	xpos: uint16;
	ypos: uint16;
} &let {
	proc: bool = $context.connection.handle_client_pointer_event(this);
} &length=5;

type ClientCutText = record {
	pad: uint8[3];
	len: uint32 &enforce(len < MAX_DATA_LENGTH);
	text: bytestring &length=len;
} &let {
	proc: bool = $context.connection.handle_client_cut_text(this);
} &length=(7 + len);

type ServerMessageType = record {
	type: uint8;
} &let {
	proc: bool = $context.connection.handle_server_message_type(type);
} &length=1;

type ServerMessage(type: uint8) = case type of {
	0 -> framebuffer_update: ServerFramebufferUpdate;
	1 -> set_color_map_entries: ServerSetColorMapEntries;
	2 -> bell: ServerBell;
	3 -> cut_text: ServerCutText;
} &let {
	proc: bool = $context.connection.handle_server_message(type);
};

type PixelData(encoding: int32, x: uint16, y: uint16, w: uint16, h: uint16) = case encoding of {
	   0   -> raw: PD_Raw(w, h);
	   1   -> copy_rec: PD_CopyRec;
	   2   -> rre: PD_RRE;
	   5   -> hextile: PD_Hextile;
	  15   -> trle: PD_TRLE;
	  16   -> zrle: PD_ZRLE;
	# TODO: binpac is not happy with negative values here
	#-239   -> cursor_pseudo: PD_PsuedoCursor;
	#-223   -> desktop_size: PD_PsuedoDesktopSize;
};

type PD_Raw(w: uint16, h: uint16) = record {
	pixels: bytestring &length=(w * h * $context.connection.get_bytes_per_pixel()) &transient;
} &length=(w * h * $context.connection.get_bytes_per_pixel());

type PD_CopyRec = record {
	xpos: uint16;
	ypos: uint16;
} &length=4;

type RRE_Subrect = record {
	pixel: bytestring &length=$context.connection.get_bytes_per_pixel();
	xpos: uint16;
	ypos: uint16;
	width: uint16;
	height: uint16;
} &length=$context.connection.get_bytes_per_pixel() + 8;

type PD_RRE = record {
	num_subrects: uint32;
	bg_pixel: bytestring &length=$context.connection.get_bytes_per_pixel();
	subrects: RRE_Subrect[num_subrects] &transient;
} &length=4 + $context.connection.get_bytes_per_pixel() + (num_subrects * ($context.connection.get_bytes_per_pixel() + 8));

type PD_Hextile = record {
	# TODO
	nothing: empty;
} &length=0;

type PD_TRLE = record {
	# TODO
	nothing: empty;
} &length=0;

type PD_ZRLE = record {
	len: uint32;
	zlib_data: bytestring &length=len &transient;
} &length=(4 + len);

type PD_PsuedoCursor(w: uint16, h: uint16) = record {
	pixels: bytestring &length=(w * h * $context.connection.get_bytes_per_pixel()) &transient;
	bitmask: bytestring &length=(h * ((w + 7) / 8)) &transient;
} &length=(w * h * $context.connection.get_bytes_per_pixel()) + (h * ((w + 7) / 8))

type PD_PsuedoDesktopSize = record {
	# Actually no further data
	nothing: empty;
} &length=0;

type Rectangle = record {
	xpos: uint16;
	ypos: uint16;
	width: uint16;
	height: uint16;
	encoding: int32;
	pixel_data: PixelData(encoding, xpos, ypos, width, height);
	# TODO add in pixel_data length to &length
} &length=12;

type ServerFramebufferUpdate = record {
	pad: uint8;
	num_rects: uint16;
	rects: Rectangle[num_rects];
	# TODO add in Rectangle[] length to &length
} &length=3;

type RGB_Value = record {
	red: uint16;
	green: uint16;
	blue: uint16;
} &length=6;

type ServerSetColorMapEntries = record {
	pad: uint8;
	first_color: uint16;
	num_colors: uint16;
	colors: RGB_Value[num_colors];
} &length=5 + (num_colors * 6)

type ServerBell = record {
	nothing: empty;
} &length=0;

type ServerCutText = record {
	pad: uint8[3];
	len: uint32 &enforce(len < MAX_DATA_LENGTH);
	text: bytestring &length=len;
} &length=(7 + len);

type RFB_PDU_request(state: uint8) = case state of {
	CLIENT_WAIT -> wait: WaitData(true);
	CLIENT_INVALID -> invalid: InvalidData(true);

	CLIENT_VERSION -> version: RFBProtocolVersion(true);
	CLIENT_AUTH_SELECTION -> authtype: RFBAuthTypeSelected; # version 3.7+
	CLIENT_AUTH_VNC_RESPONSE -> response: RFBVNCAuthenticationResponse;
	CLIENT_AUTH_ARD_RESPONSE -> ard_response: RFBSecurityARDResponse;
	CLIENT_INIT -> shareflag: RFBClientInit;

	CLIENT_MESSAGE_TYPE -> msg_type: ClientMessageType;
	CLIENT_MESSAGE -> msg: ClientMessage($context.connection.get_next_msg_type(true));
};

type RFB_PDU_response(state: uint8) = case state of {
	SERVER_WAIT -> wait: WaitData(false);
	SERVER_INVALID -> invalid: InvalidData(false);

	SERVER_VERSION -> version: RFBProtocolVersion(false);
	SERVER_AUTH_TYPE -> auth_type: RFBSecurityType;
	SERVER_AUTH_TYPE37 -> auth_types37: RFBSecurityTypes37;
	SERVER_AUTH_FAILURE -> fail_reason: RFBFailReasonString;
	SERVER_AUTH_VNC_CHALLENGE -> challenge: RFBVNCAuthenticationRequest;
	SERVER_AUTH_ARD_CHALLENGE -> ard_challenge: RFBSecurityARDChallenge;
	SERVER_AUTH_RESULT -> authresult : RFBSecurityResult;
	SERVER_INIT -> serverinit: RFBServerInit;

	SERVER_MESSAGE_TYPE -> msg_type: ServerMessageType;
	# TODO: server message parsing (framebuffer update) is not completely implemented
	#       as it is mostly uninteresting
	SERVER_MESSAGE -> msg: ServerMessage($context.connection.get_next_msg_type(false));
};

type RFB_PDU(is_orig: bool) = case is_orig of {
	true -> request: RFB_PDU_request($context.connection.get_state(true));
	false -> response: RFB_PDU_response($context.connection.get_state(false));
} &byteorder = bigendian;
