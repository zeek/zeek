enum state {
	VERSION_EXCHANGE       = 0,
	KEY_EXCHANGE_CLEARTEXT = 1,
	ENCRYPTED	       = 2,
};

enum message_id {
	SSH2_MSG_DISCONNECT		   =   1,
	SSH2_MSG_IGNORE			   =   2,
	SSH2_MSG_UNIMPLEMENTED		   =   3,
	SSH2_MSG_DEBUG			   =   4,
	SSH2_MSG_SERVICE_REQUEST	   =   5,
	SSH2_MSG_SERVICE_ACCEPT		   =   6,
	SSH2_MSG_KEXINIT		   =  20,
	SSH2_MSG_NEWKEYS		   =  21,
	SSH2_MSG_KEX_DH_GEX_REQUEST_OLD	   =  30,
	SSH2_MSG_KEX_DH_GEX_GROUP	   =  31,
	SSH2_MSG_KEX_DH_GEX_INIT	   =  32,
	SSH2_MSG_KEX_DH_GEX_REPLY	   =  33,
	SSH2_MSG_KEX_DH_GEX_REQUEST	   =  34,
	SSH2_MSG_USERAUTH_REQUEST	   =  50,
	SSH2_MSG_USERAUTH_FAILURE	   =  51,
	SSH2_MSG_USERAUTH_SUCCESS	   =  52,
	SSH2_MSG_USERAUTH_BANNER	   =  53,
	SSH2_MSG_GLOBAL_REQUEST		   =  80,
	SSH2_MSG_REQUEST_SUCCESS	   =  81,
	SSH2_MSG_REQUEST_FAILURE	   =  82,
	SSH2_MSG_CHANNEL_OPEN		   =  90,
	SSH2_MSG_CHANNEL_OPEN_CONFIRMATION =  91,
	SSH2_MSG_CHANNEL_OPEN_FAILURE	   =  92,
	SSH2_MSG_CHANNEL_WINDOW_ADJUST	   =  93,
	SSH2_MSG_CHANNEL_DATA		   =  94,
	SSH2_MSG_CHANNEL_EXTENDED_DATA	   =  95,
	SSH2_MSG_CHANNEL_EOF		   =  96,
	SSH2_MSG_CHANNEL_CLOSE		   =  97,
	SSH2_MSG_CHANNEL_REQUEST	   =  98,
	SSH2_MSG_CHANNEL_SUCCESS	   =  99,
	SSH2_MSG_CHANNEL_FAILURE	   = 100,
};

type SSH_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
	VERSION_EXCHANGE       -> version:    SSH_Version(is_orig);
	KEY_EXCHANGE_CLEARTEXT -> kex:        SSH_Key_Exchange(is_orig);
	ENCRYPTED	       -> ciphertext: bytestring &length=1 &transient;
} &byteorder=bigendian;

type SSH_Version(is_orig: bool) = record {
	version: bytestring &oneline;
} &let {
	update_state: bool = $context.connection.update_state(KEY_EXCHANGE_CLEARTEXT, is_orig);
};

type SSH_Key_Exchange_Header(is_orig: bool) = record {
	packet_length :  uint32;
	padding_length: uint8;
} &length=5;

type SSH_Key_Exchange(is_orig: bool) = record {
	header : SSH_Key_Exchange_Header(is_orig);
	payload: SSH_Payload(is_orig, header.packet_length - header.padding_length - 2);
	pad    : bytestring &length=header.padding_length;
};

type SSH_Payload_Header = record {
	message_type: uint8;
} &length=1;

type SSH_Payload(is_orig: bool, packet_length: uint32) = record {
	header:  SSH_Payload_Header;
	message: SSH_Message(is_orig, header.message_type, packet_length);
};

type SSH_Message(is_orig: bool, msg_type: uint8, packet_length: uint32) = case msg_type of {
	SSH2_MSG_KEXINIT                -> kexinit:            SSH_KEXINIT(packet_length);
	SSH2_MSG_KEX_DH_GEX_REQUEST     -> dh_gex_request:     SSH_DH_GEX_REQUEST(packet_length);
	SSH2_MSG_KEX_DH_GEX_REQUEST_OLD -> dh_gex_request_old: SSH_DH_GEX_REQUEST_OLD(packet_length);
	SSH2_MSG_KEX_DH_GEX_GROUP       -> dh_gex_group:       SSH_DH_GEX_GROUP(packet_length);
	SSH2_MSG_KEX_DH_GEX_INIT        -> dh_gex_init:        SSH_DH_GEX_INIT(packet_length);
	SSH2_MSG_KEX_DH_GEX_REPLY       -> dh_gex_reply:       SSH_DH_GEX_REPLY(packet_length);
	SSH2_MSG_NEWKEYS	        -> new_keys:	       bytestring &length=packet_length;	
} &let {
	detach: bool = $context.connection.update_state(ENCRYPTED, is_orig) &if(msg_type == SSH2_MSG_NEWKEYS);
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

type ssh_string = record {
	len: uint32;
	val: bytestring &length=len;
};

refine connection SSH_Conn += {
	%member{
		int state_up_;
		int state_down_;
	%}

	%init{
		state_up_   = VERSION_EXCHANGE;
		state_down_ = VERSION_EXCHANGE;
	%}

	function get_state(is_orig: bool): int
		%{
		if ( is_orig )
			return state_up_;
		else
			return state_down_;
		%}

	function update_state(s: state, is_orig: bool): bool
		%{
		if ( is_orig )
			state_up_ = s;
		else
			state_down_ = s;
		return true;
		%}

};