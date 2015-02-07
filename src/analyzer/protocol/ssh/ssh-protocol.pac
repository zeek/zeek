enum version {
	SSH1 = 1,
	SSH2 = 2,
	UNK  = 3,
};

enum state {
	VERSION_EXCHANGE	= 0,
	KEX_INIT		= 1,
	KEX_DH_GEX		= 2,
	KEX_DH			= 3,
	KEX_ECC			= 4,
	KEX_GSS			= 5,
	KEX_RSA			= 6,
	ENCRYPTED		= 7,
};

# diffie-hellman-group1-sha1	[RFC4253]	Section 8.1
# diffie-hellman-group14-sha1	[RFC4253]	Section 8.2
enum KEX_DH_message_id {
	SSH_MSG_KEXDH_INIT  = 30,
	SSH_MSG_KEXDH_REPLY = 31,
};

# diffie-hellman-group-exchange-sha1	[RFC4419]	Section 4.1
# diffie-hellman-group-exchange-sha256	[RFC4419]	Section 4.2
enum KEX_DH_GEX_message_id {
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD	= 30,
	SSH_MSG_KEX_DH_GEX_GROUP	= 31,
	SSH_MSG_KEX_DH_GEX_INIT		= 32,
	SSH_MSG_KEX_DH_GEX_REPLY	= 33,
	SSH_MSG_KEX_DH_GEX_REQUEST	= 34,
};

# rsa1024-sha1		[RFC4432]
# rsa2048-sha256	[RFC4432]
enum KEX_RSA_message_id {
	SSH_MSG_KEXRSA_PUBKEY	= 30,
    SSH_MSG_KEXRSA_SECRET	= 31,
    SSH_MSG_KEXRSA_DONE		= 32,
};

# gss-group1-sha1-*	[RFC4462]	Section 2.3
# gss-group14-sha1-*	[RFC4462]	Section 2.4
# gss-gex-sha1-*	[RFC4462]	Section 2.5
# gss-*			[RFC4462]	Section 2.6
enum KEX_GSS_message_id {
   	SSH_MSG_KEXGSS_INIT         =  30,
   	SSH_MSG_KEXGSS_CONTINUE     =  31,
   	SSH_MSG_KEXGSS_COMPLETE     =  32,
   	SSH_MSG_KEXGSS_HOSTKEY      =  33,
   	SSH_MSG_KEXGSS_ERROR        =  34,
   	SSH_MSG_KEXGSS_GROUPREQ     =  40,
   	SSH_MSG_KEXGSS_GROUP        =  41,
};

# ecdh-sha2-*			[RFC5656]
enum KEX_ECDH_message_id {
	SSH_MSG_KEX_ECDH_INIT    = 30,
	SSH_MSG_KEX_ECDH_REPLY   = 31,
};

# ecmqv-sha2			[RFC5656]
enum KEX_ECMQV_message_id {
	SSH_MSG_ECMQV_INIT  = 30,
	SSH_MSG_ECMQV_REPLY = 31,
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
	MSG_DISCONNECT		=   1,
	MSG_IGNORE		=   2,
	MSG_UNIMPLEMENTED	=   3,
	MSG_DEBUG		=   4,
	MSG_SERVICE_REQUEST	=   5,
	MSG_SERVICE_ACCEPT	=   6,
	MSG_KEXINIT		=  20,
	MSG_NEWKEYS		=  21,
};

## SSH Generic

type SSH_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
	VERSION_EXCHANGE	-> version:    	SSH_Version(is_orig);
	KEX_INIT 		-> kex:        	SSH_Key_Exchange(is_orig);
	KEX_DH_GEX		-> kex_dh_gex: 	SSH_Key_Exchange_DH_GEX(is_orig);
	KEX_DH			-> kex_dh: 		SSH_Key_Exchange_DH(is_orig);
	KEX_ECC			-> kex_ecc: 	SSH_Key_Exchange_ECC(is_orig);
	KEX_GSS			-> kex_gss: 	SSH_Key_Exchange_GSS(is_orig);
	KEX_RSA			-> kex_rsa: 	SSH_Key_Exchange_RSA(is_orig);
} &byteorder=bigendian;

type SSH_Version(is_orig: bool) = record {
	version: bytestring &oneline;
	pad: bytestring &length=0 &transient;
} &let {
	update_state  : bool = $context.connection.update_state(KEX_INIT, is_orig);
	update_version: bool = $context.connection.update_version(version, is_orig);
};

type SSH_Key_Exchange(is_orig: bool) = case $context.connection.get_version() of {
	SSH1    -> ssh1_msg: SSH1_Key_Exchange(is_orig);
	SSH2    -> ssh2_msg: SSH2_Key_Exchange(is_orig);
};

## SSH1

type SSH1_Key_Exchange(is_orig: bool) = record {
	packet_length: uint32;
	pad_fill     : bytestring &length = 8 - (packet_length % 8);
	msg_type     : uint8;
	message	     : SSH1_Message(is_orig, msg_type, packet_length-5);
	crc          : uint32;
} &length = packet_length + 4 + 8 - (packet_length % 8);

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

type ssh1_mp_int = record {
	len: uint16;
	val: bytestring &length=(len+7)/8;
};

## SSH2

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

type SSH2_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	MSG_KEXINIT	-> kexinit:  SSH_KEXINIT(length, is_orig);
	default	-> unknown: bytestring &length=length;
} &let {
	detach: bool = $context.connection.update_state(ENCRYPTED, is_orig) &if(msg_type == MSG_NEWKEYS);
};

type SSH_KEXINIT(length: uint32, is_orig: bool) = record {
	cookie                                  : bytestring &length=16;
	kex_algorithms                          : ssh_string;
	server_host_key_algorithms              : ssh_string;
	encryption_algorithms_client_to_server  : ssh_string;
	encryption_algorithms_server_to_client  : ssh_string;
	mac_algorithms_client_to_server         : ssh_string;
	mac_algorithms_server_to_client         : ssh_string;
	compression_algorithms_client_to_server : ssh_string;
	compression_algorithms_server_to_client : ssh_string;
	languages_client_to_server				: ssh_string;
	languages_server_to_client				: ssh_string;
	first_kex_packet_follows				: uint8;
	reserved								: uint32;
} &let {
	proc_kex : bool = $context.connection.update_kex(kex_algorithms.val, is_orig);
} &length=length;

# KEX_DH exchanges

type SSH_Key_Exchange_DH(is_orig: bool) = record {
	header  : SSH2_Key_Exchange_Header;
	payload : SSH_Key_Exchange_DH_Message(is_orig, header.msg_type, header.payload_length);
	pad		: bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH_Key_Exchange_DH_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXDH_INIT	-> init		: SSH_DH_GEX_INIT(length);
	SSH_MSG_KEXDH_REPLY	-> reply	: SSH_DH_GEX_REPLY(length);
};

# KEX_DH_GEX exchanges

type SSH_Key_Exchange_DH_GEX(is_orig: bool) = record {
	header  : SSH2_Key_Exchange_Header;
	payload : SSH_Key_Exchange_DH_GEX_Message(is_orig, header.msg_type, header.payload_length);
	pad		: bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH_Key_Exchange_DH_GEX_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD	-> request_old	: SSH_DH_GEX_REQUEST_OLD;
	SSH_MSG_KEX_DH_GEX_REQUEST		-> request		: SSH_DH_GEX_REQUEST;
	SSH_MSG_KEX_DH_GEX_GROUP		-> group		: SSH_DH_GEX_GROUP(length);
	SSH_MSG_KEX_DH_GEX_INIT			-> init			: SSH_DH_GEX_INIT(length);
	SSH_MSG_KEX_DH_GEX_REPLY		-> reply		: SSH_DH_GEX_REPLY(length);
};

type SSH_DH_GEX_REQUEST = record {
	min: uint32;
	n  : uint32;
	max: uint32;
} &length=12;

type SSH_DH_GEX_REQUEST_OLD = record {
	n: uint32;
} &length=4;

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

# KEX_RSA exchanges

type SSH_Key_Exchange_RSA(is_orig: bool) = record {
	header  : SSH2_Key_Exchange_Header;
	payload : SSH_Key_Exchange_RSA_Message(is_orig, header.msg_type, header.payload_length);
	pad		: bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH_Key_Exchange_RSA_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXRSA_PUBKEY	-> pubkey	: SSH_RSA_PUBKEY(length);
	SSH_MSG_KEXRSA_SECRET	-> secret	: SSH_RSA_SECRET(length);
	SSH_MSG_KEXRSA_DONE		-> done		: SSH_RSA_DONE(length);
};

type SSH_RSA_PUBKEY(length: uint32) = record {
	k_s: ssh_string;
	k_t: ssh_string;
} &length=length;

type SSH_RSA_SECRET(length: uint32) = record {
	encrypted_payload: ssh_string;
} &length=length;

type SSH_RSA_DONE(length: uint32) = record {
	signature: ssh_string;
} &length=length;

# KEX_GSS exchanges

type SSH_Key_Exchange_GSS(is_orig: bool) = record {
	header  : SSH2_Key_Exchange_Header;
	payload : SSH_Key_Exchange_GSS_Message(is_orig, header.msg_type, header.payload_length);
	pad		: bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH_Key_Exchange_GSS_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXGSS_INIT			-> init		: SSH_GSS_INIT(length);
	SSH_MSG_KEXGSS_CONTINUE		-> cont		: SSH_GSS_CONTINUE(length);
	SSH_MSG_KEXGSS_COMPLETE		-> complete	: SSH_GSS_COMPLETE(length);
	SSH_MSG_KEXGSS_HOSTKEY		-> hostkey	: SSH_GSS_HOSTKEY(length);
	SSH_MSG_KEXGSS_ERROR		-> error	: SSH_GSS_ERROR(length);
	SSH_MSG_KEXGSS_GROUPREQ		-> groupreq	: SSH_DH_GEX_REQUEST;
	SSH_MSG_KEXGSS_GROUP		-> group	: SSH_DH_GEX_GROUP(length);
};

type SSH_GSS_INIT(length: uint32) = record {
	output_token: ssh_string;
	e			: ssh_string;
} &length=length;

type SSH_GSS_CONTINUE(length: uint32) = record {
	output_token: ssh_string;		
} &length=length;

type SSH_GSS_COMPLETE(length: uint32) = record {
	f				: ssh_string;
	per_msg_token	: ssh_string;
	have_token		: uint8;
	parse_token		: case have_token of {
		0 		-> no_token: empty;
		default -> token: ssh_string;
	};
} &length=length;

type SSH_GSS_HOSTKEY(length: uint32) = record {
	k_s: ssh_string;
} &length=length;

type SSH_GSS_ERROR(length: uint32) = record {
	major_status: uint32;
	minor_status: uint32;
	message		: ssh_string;
	language	: ssh_string;
} &length=length;

# KEX_ECDH and KEX_ECMQV exchanges

type SSH_Key_Exchange_ECC(is_orig: bool) = record {
	header  : SSH2_Key_Exchange_Header;
	payload : SSH_Key_Exchange_ECC_Message(is_orig, header.msg_type, header.payload_length);
	pad		: bytestring &length=header.padding_length;
} &length=header.packet_length + 4;

type SSH_Key_Exchange_ECC_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEX_ECDH_INIT	-> init		: SSH_ECC_INIT(length);
	SSH_MSG_KEX_ECDH_REPLY	-> reply	: SSH_ECC_REPLY(length);
};

# This deviates from the RFC. SSH_MSG_KEX_ECDH_INIT and
# SSH_MSG_KEX_ECMQV_INIT can be parsed the same way.
type SSH_ECC_INIT(length: uint32) = record {
	q_c: ssh_string;	
};

# This deviates from the RFC. SSH_MSG_KEX_ECDH_REPLY and
# SSH_MSG_KEX_ECMQV_REPLY can be parsed the same way.
type SSH_ECC_REPLY(length: uint32) = record {
	k_s			: ssh_string;
	q_s			: ssh_string;
	signature	: ssh_string;	
};

type ssh_string = record {
	len: uint32;
	val: bytestring &length=len;
};

type ssh_host_key = record {
	len: uint32;
	key_type: ssh_string;
	key: ssh_string;
} &length=(len + 4);

## Done with types

refine connection SSH_Conn += {
	%member{
		int state_up_;
		int state_down_;
		int version_;

		bool kex_orig_;
		bool kex_seen_;
		bytestring kex_algs_cache_;
		bytestring kex_algorithm_;
	%}

	%init{
		state_up_   = VERSION_EXCHANGE;
		state_down_ = VERSION_EXCHANGE;
		version_    = UNK;
		
		kex_seen_ = false;
		kex_orig_ = false;
		kex_algs_cache_ = bytestring();
		kex_algorithm_ = bytestring();
	%}

	%cleanup{
		kex_algorithm_.free();
		kex_algs_cache_.free();
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

	function update_kex_state_if_equal(s: string, to_state: state): bool
		%{
		if ( strcmp(c_str(kex_algorithm_), s.c_str()) == 0 )
			{
			update_state(to_state, true);
			update_state(to_state, false);
			return true;
			}
		return false;
		%}
		
	function update_kex_state_if_startswith(s: string, to_state: state): bool
		%{
		if ( (uint) kex_algorithm_.length() < s.length() )
			return false;
		
		if ( strcmp(std_str(kex_algorithm_).substr(0, s.length()).c_str(), s.c_str()) == 0 )
			{
			update_state(to_state, true);
			update_state(to_state, false);
			return true;
			}
		return false;
		%}
		
	function update_kex(algs: bytestring, orig: bool): bool
		%{
		if ( !kex_seen_ )
			{
			kex_seen_ = true;
			kex_orig_ = orig;
			kex_algs_cache_.init(${algs}.data(), ${algs}.length());

			return false;
			}
		else if ( kex_orig_ == orig )
			return false;

		VectorVal* client_list = name_list_to_vector(orig ? algs : kex_algs_cache_);
		VectorVal* server_list = name_list_to_vector(orig ? kex_algs_cache_ : algs);

		for ( unsigned int i = 0; i < client_list->Size(); ++i)
			{
			for ( unsigned int j = 0; j < server_list->Size(); ++j)
				{
				if ( strcmp((const char *) client_list->Lookup(i)->AsStringVal()->Bytes(),
				   	 	    (const char *) server_list->Lookup(j)->AsStringVal()->Bytes()) == 0 )
					{
					kex_algorithm_.init((const uint8 *) client_list->Lookup(i)->AsStringVal()->Bytes(),
									    client_list->Lookup(i)->AsStringVal()->Len());

					Unref(client_list);
					Unref(server_list);

					// UNTESTED
					if ( update_kex_state_if_equal("rsa1024-sha1", KEX_RSA) )
						return true;
					// UNTESTED
					if ( update_kex_state_if_equal("rsa2048-sha256", KEX_RSA) )
						return true;

					// UNTESTED
					if ( update_kex_state_if_equal("diffie-hellman-group1-sha1", KEX_DH) )
						return true;
					// UNTESTED
					if ( update_kex_state_if_equal("diffie-hellman-group14-sha1", KEX_DH) )
						return true;

					if ( update_kex_state_if_equal("diffie-hellman-group-exchange-sha1", KEX_DH_GEX) )
						return true;
					if ( update_kex_state_if_equal("diffie-hellman-group-exchange-sha256", KEX_DH_GEX) )
						return true;

					if ( update_kex_state_if_startswith("gss-group1-sha1-", KEX_GSS) )
						return true;
					if ( update_kex_state_if_startswith("gss-group14-sha1-", KEX_GSS) )
						return true;
					if ( update_kex_state_if_startswith("gss-gex-sha1-", KEX_GSS) )
						return true;
					if ( update_kex_state_if_startswith("gss-", KEX_GSS) )
						return true;

					if ( update_kex_state_if_startswith("ecdh-sha2-", KEX_ECC) )
						return true;
					if ( update_kex_state_if_equal("ecmqv-sha2", KEX_ECC) )
						return true;
					if ( update_kex_state_if_equal("curve25519-sha256@libssh.org", KEX_ECC) )
						return true;


					bro_analyzer()->Weird(fmt("ssh_unknown_kex_algorithm=%s", c_str(kex_algorithm_)));
					return true;
					
					}
				}
			}
			
		Unref(client_list);
		Unref(server_list);

		return true;
			
		%}

		
};