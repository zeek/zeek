enum version {
	SSH1 = 1,
	SSH2 = 2,
	UNK  = 3,
};

enum state {
	VERSION_EXCHANGE       = 0,
	KEY_EXCHANGE_CLEARTEXT = 1,
	ENCRYPTED	       = 2,
};

enum ssh1_message_id {
	SSH_MSG_NONE				=  0,
	SSH_MSG_DISCONNECT			=  1,
	SSH_SMSG_PUBLIC_KEY			=  2,
	SSH_CMSG_SESSION_KEY			=  3,
	SSH_CMSG_USER				=  4,
	SSH_CMSG_AUTH_RHOSTS			=  5,
	SSH_CMSG_AUTH_RSA			=  6,
	SSH_SMSG_AUTH_RSA_CHALLENGE		=  7,
	SSH_CMSG_AUTH_RSA_RESPONSE		=  8,
	SSH_CMSG_AUTH_PASSWORD			=  9,
	SSH_CMSG_REQUEST_PTY			= 10,
	SSH_CMSG_WINDOW_SIZE			= 11,
	SSH_CMSG_EXEC_SHELL			= 12,
	SSH_CMSG_EXEC_CMD			= 13,
	SSH_SMSG_SUCCESS			= 14,
	SSH_SMSG_FAILURE			= 15,
	SSH_CMSG_STDIN_DATA			= 16,
	SSH_SMSG_STDOUT_DATA			= 17,
	SSH_SMSG_STDERR_DATA			= 18,
	SSH_CMSG_EOF				= 19,
	SSH_SMSG_EXITSTATUS			= 20,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION	= 21,
	SSH_MSG_CHANNEL_OPEN_FAILURE		= 22,
	SSH_MSG_CHANNEL_DATA			= 23,
	SSH_MSG_CHANNEL_CLOSE			= 24,
	SSH_MSG_CHANNEL_CLOSE_CONFIRMATION	= 25,
	SSH_CMSG_X11_REQUEST_FORWARDING_OLD	= 26,
	SSH_SMSG_X11_OPEN			= 27,
	SSH_CMSG_PORT_FORWARD_REQUEST		= 28,
	SSH_MSG_PORT_OPEN			= 29,
	SSH_CMSG_AGENT_REQUEST_FORWARDING	= 30,
	SSH_SMSG_AGENT_OPEN			= 31,
	SSH_MSG_IGNORE				= 32,
	SSH_CMSG_EXIT_CONFIRMATION		= 33,
	SSH_CMSG_X11_REQUEST_FORWARDING		= 34,
	SSH_CMSG_AUTH_RHOSTS_RSA		= 35,
	SSH_MSG_DEBUG				= 36,
	SSH_CMSG_REQUEST_COMPRESSION		= 37,
	SSH_CMSG_MAX_PACKET_SIZE		= 38,
	SSH_CMSG_AUTH_TIS			= 39,
	SSH_SMSG_AUTH_TIS_CHALLENGE		= 40,
	SSH_CMSG_AUTH_TIS_RESPONSE		= 41,
	SSH_CMSG_AUTH_KERBEROS			= 42,
	SSH_SMSG_AUTH_KERBEROS_RESPONSE		= 43,
	SSH_CMSG_HAVE_KERBEROS_TGT		= 44,
};

enum ssh2_message_id {
	MSG_DISCONNECT			=   1,
	MSG_IGNORE			=   2,
	MSG_UNIMPLEMENTED		=   3,
	MSG_DEBUG			=   4,
	MSG_SERVICE_REQUEST		=   5,
	MSG_SERVICE_ACCEPT		=   6,
	MSG_KEXINIT			=  20,
	MSG_NEWKEYS			=  21,
	MSG_KEX_DH_GEX_REQUEST_OLD	=  30,
	MSG_KEX_DH_GEX_GROUP		=  31,
	MSG_KEX_DH_GEX_INIT		=  32,
	MSG_KEX_DH_GEX_REPLY		=  33,
	MSG_KEX_DH_GEX_REQUEST		=  34,
	MSG_USERAUTH_REQUEST		=  50,
	MSG_USERAUTH_FAILURE		=  51,
	MSG_USERAUTH_SUCCESS		=  52,
	MSG_USERAUTH_BANNER		=  53,
	MSG_GLOBAL_REQUEST		=  80,
	MSG_REQUEST_SUCCESS		=  81,
	MSG_REQUEST_FAILURE		=  82,
	MSG_CHANNEL_OPEN		=  90,
	MSG_CHANNEL_OPEN_CONFIRMATION	=  91,
	MSG_CHANNEL_OPEN_FAILURE	=  92,
	MSG_CHANNEL_WINDOW_ADJUST	=  93,
	MSG_CHANNEL_DATA		=  94,
	MSG_CHANNEL_EXTENDED_DATA	=  95,
	MSG_CHANNEL_EOF			=  96,
	MSG_CHANNEL_CLOSE		=  97,
	MSG_CHANNEL_REQUEST		=  98,
	MSG_CHANNEL_SUCCESS		=  99,
	MSG_CHANNEL_FAILURE		= 100,
};

type SSH_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
	VERSION_EXCHANGE       -> version:    SSH_Version(is_orig);
	KEY_EXCHANGE_CLEARTEXT -> kex:        SSH_Key_Exchange(is_orig);
	ENCRYPTED	       -> ciphertext: bytestring &length=1 &transient;
} &byteorder=bigendian;

type SSH_Version(is_orig: bool) = record {
	version: bytestring &oneline;
	pad: bytestring &length=0 &transient;
} &let {
	update_state  : bool = $context.connection.update_state(KEY_EXCHANGE_CLEARTEXT, is_orig);
	update_version: bool = $context.connection.update_version(version, is_orig);
};

type SSH_Key_Exchange(is_orig: bool) = case $context.connection.get_version() of {
	SSH1    -> ssh1_msg: SSH1_Key_Exchange(is_orig);
	SSH2    -> ssh2_msg: SSH2_Key_Exchange(is_orig);
};

type SSH1_Key_Exchange(is_orig: bool) = record {
	packet_length: uint32;
	pad_fill     : bytestring &length = 8 - (packet_length % 8);
	msg_type     : uint8;
	message	     : SSH1_Message(is_orig, msg_type, packet_length-5);
	crc          : uint32;
} &length = packet_length + 4 + 8 - (packet_length % 8);

type SSH2_Key_Exchange_Header = record {
	packet_length : uint32;
	padding_length: uint8;
	msg_type      : uint8;
} &let {
	payload_length: uint32 = packet_length - padding_length - 2;
} &length=6;

type SSH2_Key_Exchange(is_orig: bool) = record {
	header	: SSH2_Key_Exchange_Header;
	payload : SSH2_Message(is_orig, header.msg_type, header.payload_length);
	pad     : bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH1_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_SMSG_PUBLIC_KEY	-> public_key:	SSH1_PUBLIC_KEY(length);
	SSH_CMSG_SESSION_KEY	-> session_key:	SSH1_SESSION_KEY(length);
} &let {
	detach: bool = $context.connection.update_state(ENCRYPTED, is_orig);
};

type SSH1_PUBLIC_KEY(length: uint32) = record {
	cookie			: bytestring &length=8;
	server_key		: uint32;
	server_key_p		: ssh1_mp_int;
	server_key_e		: ssh1_mp_int;
	host_key		: uint32;
	host_key_p		: ssh1_mp_int;
	host_key_e		: ssh1_mp_int;
	flags			: uint32;
	supported_ciphers	: uint32;
	supported_auths		: uint32;
} &length=length;

type SSH1_SESSION_KEY(length: uint32) = record {
	cipher		: uint8;
	cookie		: bytestring &length=8;
	session_key	: ssh1_mp_int;
	flags		: uint32;
} &length=length;

type SSH2_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	MSG_KEXINIT                -> kexinit:            SSH_KEXINIT(length);
	MSG_KEX_DH_GEX_REQUEST     -> dh_gex_request:     SSH_DH_GEX_REQUEST(length);
	MSG_KEX_DH_GEX_REQUEST_OLD -> dh_gex_request_old: SSH_DH_GEX_REQUEST_OLD(length);
	MSG_KEX_DH_GEX_GROUP       -> dh_gex_group:       SSH_DH_GEX_GROUP(length);
	MSG_KEX_DH_GEX_INIT        -> dh_gex_init:        SSH_DH_GEX_INIT(length);
	MSG_KEX_DH_GEX_REPLY       -> dh_gex_reply:       SSH_DH_GEX_REPLY(length);
	MSG_NEWKEYS	           -> new_keys:	          bytestring &length=length;
} &let {
	detach: bool = $context.connection.update_state(ENCRYPTED, is_orig) &if(msg_type == MSG_NEWKEYS);
};

type SSH_KEXINIT(length: uint32) = record {
	cookie                                  : bytestring &length=16;
	kex_algorithms                          : ssh_string;
	server_host_key_algorithms              : ssh_string;
	encryption_algorithms_client_to_server  : ssh_string;
	encryption_algorithms_server_to_client  : ssh_string;
	mac_algorithms_client_to_server         : ssh_string;
	mac_algorithms_server_to_client         : ssh_string;
	compression_algorithms_client_to_server : ssh_string;
	compression_algorithms_server_to_client : ssh_string;
	languages_client_to_server		: ssh_string;
	languages_server_to_client		: ssh_string;
	first_kex_packet_follows		: uint8;
	reserved				: uint32;
} &length=length;

type SSH_DH_GEX_REQUEST(length: uint32) = record {
	min: uint32;
	n  : uint32;
	max: uint32;
} &length=12;

type SSH_DH_GEX_REQUEST_OLD(length: uint32) = record {
	payload: bytestring &length=length;
} &length=length;

type SSH_DH_GEX_GROUP(length: uint32) = record {
	p: ssh_string;
	g: ssh_string;
} &length=length;

type SSH_DH_GEX_INIT(length: uint32) = record {
	e: ssh_string;
} &length=length;

type SSH_DH_GEX_REPLY(length: uint32) = record {
	k_s      : ssh_string;
	f        : ssh_string;
	signature: ssh_string;
} &length=length;

type ssh1_mp_int = record {
	len: uint16;
	val: bytestring &length=(len+7)/8;
};

type ssh_string = record {
	len: uint32;
	val: bytestring &length=len;
};

refine connection SSH_Conn += {
	%member{
		int state_up_;
		int state_down_;
		int version_;
	%}

	%init{
		state_up_   = VERSION_EXCHANGE;
		state_down_ = VERSION_EXCHANGE;
		version_    = UNK;
	%}

	function get_state(is_orig: bool): int
		%{
		if ( is_orig )
			{
			return state_up_;
			}
		else
			{
			return state_down_;
			}
		%}

	function update_state(s: state, is_orig: bool): bool
		%{
		if ( is_orig )
			state_up_ = s;
		else
			state_down_ = s;
		return true;
		%}

	function get_version(): int
		%{
		return version_;
		%}

	function update_version(v: bytestring, is_orig: bool): bool
		%{
		if ( is_orig && ( v.length() >= 4 ) )
			{
			if ( v[4] == '2' )
				version_ = SSH2;
			if ( v[4] == '1' )
				version_ = SSH1;
			}
		return true;
		%}

};