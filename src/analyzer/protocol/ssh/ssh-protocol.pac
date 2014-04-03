enum state {
	VERSION_EXCHANGE       = 0,
	KEY_EXCHANGE_CLEARTEXT = 1,
	ENCRYPTED	       = 2,
};

enum message_id {
	SSH_MSG_DISCONNECT		  =   1,
	SSH_MSG_IGNORE			  =   2,
	SSH_MSG_UNIMPLEMENTED		  =   3,
        SSH_MSG_DEBUG			  =   4,
        SSH_MSG_SERVICE_REQUEST		  =   5,
        SSH_MSG_SERVICE_ACCEPT		  =   6,
        SSH_MSG_KEXINIT			  =  20,
        SSH_MSG_NEWKEYS			  =  21,
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD	  =  30,
	SSH_MSG_KEX_DH_GEX_GROUP	  =  31,
	SSH_MSG_KEX_DH_GEX_INIT		  =  32,
	SSH_MSG_KEX_DH_GEX_REPLY	  =  33,
	SSH_MSG_KEX_DH_GEX_REQUEST	  =  34,
        SSH_MSG_USERAUTH_REQUEST	  =  50,
        SSH_MSG_USERAUTH_FAILURE	  =  51,
        SSH_MSG_USERAUTH_SUCCESS	  =  52,
        SSH_MSG_USERAUTH_BANNER		  =  53,
        SSH_MSG_GLOBAL_REQUEST		  =  80,
        SSH_MSG_REQUEST_SUCCESS		  =  81,
        SSH_MSG_REQUEST_FAILURE		  =  82,
        SSH_MSG_CHANNEL_OPEN		  =  90,
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION =  91,
        SSH_MSG_CHANNEL_OPEN_FAILURE	  =  92,
        SSH_MSG_CHANNEL_WINDOW_ADJUST	  =  93,
        SSH_MSG_CHANNEL_DATA		  =  94,
        SSH_MSG_CHANNEL_EXTENDED_DATA	  =  95,
        SSH_MSG_CHANNEL_EOF		  =  96,
        SSH_MSG_CHANNEL_CLOSE		  =  97,
        SSH_MSG_CHANNEL_REQUEST		  =  98,
        SSH_MSG_CHANNEL_SUCCESS		  =  99,
        SSH_MSG_CHANNEL_FAILURE		  = 100,
};

type SSH_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
		VERSION_EXCHANGE       -> version:   SSH_Version(is_orig);
		KEY_EXCHANGE_CLEARTEXT -> kex:       SSH_Key_Exchange(is_orig);
		ENCRYPTED -> unk: bytestring &length=100;
} &byteorder=bigendian;

type SSH_Version(is_orig: bool) = record {
	version: bytestring &oneline;
} &let {
	update_state: bool = $context.connection.update_state(KEY_EXCHANGE_CLEARTEXT, is_orig);
};

type SSH_Key_Exchange_Header(is_orig: bool) = record {
	packet_length: uint32;
	padding_length: uint8;
} &length=5;

type SSH_Key_Exchange(is_orig: bool) = record {
	header : SSH_Key_Exchange_Header(is_orig);
	payload: SSH_Payload(is_orig, header.packet_length - header.padding_length - 2);
	pad    : bytestring &length=header.padding_length;
};

type SSH_Payload_Header(length: uint32) = record {
	message_type: uint8;
} &length=1;

type SSH_Payload(is_orig: bool, packet_length: uint32) = record {
	header:  SSH_Payload_Header(packet_length);
	message: SSH_Message(is_orig, header.message_type, packet_length);
};

type SSH_Message(is_orig: bool, msg_type: uint8, packet_length: uint32) = case msg_type of {
	SSH_MSG_KEXINIT            -> kexinit:        SSH_KEXINIT(is_orig, packet_length);
	SSH_MSG_KEX_DH_GEX_REQUEST -> dh_gex_request: SSH_DH_GEX_REQUEST(is_orig, packet_length);
	SSH_MSG_KEX_DH_GEX_GROUP   -> dh_gex_group:   SSH_DH_GEX_GROUP(is_orig, packet_length);
	SSH_MSG_KEX_DH_GEX_INIT    -> dh_gex_init:    SSH_DH_GEX_INIT(is_orig, packet_length);
	SSH_MSG_KEX_DH_GEX_REPLY   -> dh_gex_reply:   SSH_DH_GEX_REPLY(is_orig, packet_length);
	default -> unknown: bytestring &length=packet_length;
} &let {
	detach: bool = $context.connection.update_state(ENCRYPTED, is_orig) &if(msg_type == SSH_MSG_NEWKEYS);
};

type SSH_KEXINIT(is_orig: bool, length: uint32) = record {
	cookie                                      : bytestring &length=16;
	kex_algorithms_len                          : uint32;
	kex_algorithms                              : bytestring &length=kex_algorithms_len;
	server_host_key_algorithms_len              : uint32;
	server_host_key_algorithms                  : bytestring &length=server_host_key_algorithms_len;
	encryption_algorithms_client_to_server_len  : uint32;
	encryption_algorithms_client_to_server      : bytestring &length=encryption_algorithms_client_to_server_len;
	encryption_algorithms_server_to_client_len  : uint32;
	encryption_algorithms_server_to_client      : bytestring &length=encryption_algorithms_server_to_client_len;
	mac_algorithms_client_to_server_len         : uint32;
	mac_algorithms_client_to_server             : bytestring &length=mac_algorithms_client_to_server_len;
	mac_algorithms_server_to_client_len         : uint32;
	mac_algorithms_server_to_client             : bytestring &length=mac_algorithms_server_to_client_len;
	compression_algorithms_client_to_server_len : uint32;
	compression_algorithms_client_to_server     : bytestring &length=compression_algorithms_client_to_server_len;
	compression_algorithms_server_to_client_len : uint32;
	compression_algorithms_server_to_client     : bytestring &length=compression_algorithms_server_to_client_len;
	languages_client_to_server_len		    : uint32;
	languages_client_to_server		    : bytestring &length=languages_client_to_server_len;
	languages_server_to_client_len		    : uint32;
	languages_server_to_client		    : bytestring &length=languages_server_to_client_len;
	first_kex_packet_follows		    : uint8;
	reserved				    : uint32;
} &length=length;

type SSH_DH_GEX_REQUEST(is_orig: bool, length: uint32) = record {
	min: uint32;
	n  : uint32;
	max: uint32;
} &length=12;

type SSH_DH_GEX_GROUP(is_orig: bool, length: uint32) = record {
	p: mpint;
	g: mpint;
} &length=length;

type SSH_DH_GEX_INIT(is_orig: bool, length: uint32) = record {
	e: mpint;
} &length=length;

type SSH_DH_GEX_REPLY(is_orig: bool, length: uint32) = record {
	k_s      : ssh_string;
	f        : mpint;
	signature: ssh_string;
} &length=length;

#type SSH_NEWKEYS(is_orig: bool, length: uint32) = record {
#	blah: ;
#} &let {
#	detach: bool = $context.connection.detach();
#} &length=0;

type mpint = record {
	len: uint32;
	val: bytestring &length=len;
};

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