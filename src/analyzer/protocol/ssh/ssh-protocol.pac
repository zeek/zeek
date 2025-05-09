%include consts.pac

%extern{
#include "zeek/ZeekString.h"
%}

# Common constructs across SSH1 and SSH2
########################################

# We have 3 basic types of messages:
#
#  - SSH_Version messages just have a string with the banner string of the client or server
#  - Encrypted messages have no usable data, so we'll just ignore them as best we can.
#  - Finally, key exchange messages have a common format.

type EncryptedByte(is_orig: bool) = record {
	encrypted : bytestring &length=1 &transient;
} &let {
proc: bool = $context.connection.inc_encrypted_byte_count_in_current_segment();
};

type SSH_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
	VERSION_EXCHANGE -> version   : SSH_Version_Switch(is_orig);
	ENCRYPTED        -> encrypted : EncryptedByte(is_orig);
	default          -> kex       : SSH_Key_Exchange(is_orig);
} &byteorder=bigendian;

type SSH_Version_Switch(is_orig: bool) = case is_orig of {
	true -> client_version : SSH_Version_Client;
	false -> server_version: SSH_Version_Server;
};

# SSH servers can have banners before their SSH version. Which... fun.
type SSH_Version_Server = record {
	version: RE/(SSH-.*)?/;
	# only UTF-8 data. This doesn't catch all bad cases, but some
	nonversiondata: RE/([^[\xC0-\xC1]|[\xF5-\xFF]])*/;
} &let {
	update_state   : bool = $context.connection.update_state(KEX_INIT, false) &if(sizeof(version) > 0);
	update_version : bool = $context.connection.update_version(version, false) &if(sizeof(version) > 0);
} &oneline;

# SSH clients _always_ have to send a line starting with SSH- first.
type SSH_Version_Client = record {
	version : RE/SSH-.*/ &oneline;
} &let {
	update_state   : bool = $context.connection.update_state(KEX_INIT, true);
	update_version : bool = $context.connection.update_version(version, true);
};

type SSH_Key_Exchange(is_orig: bool) = record {
	packet_length: uint32;
	key_ex: case $context.connection.get_version() of {
		SSH1 -> ssh1_msg : SSH1_Key_Exchange(is_orig, packet_length);
		SSH2 -> ssh2_msg : SSH2_Key_Exchange(is_orig, packet_length);
	};
} &length = $context.flow.get_kex_length($context.connection.get_version(), packet_length);

# SSH1 constructs
#################

type SSH1_Key_Exchange(is_orig: bool, packet_length: uint32) = record {
	pad_fill      : bytestring &length = 8 - (packet_length % 8);
	msg_type      : uint8;
	message       : SSH1_Message(is_orig, msg_type, packet_length - 5);
	crc           : uint32;
} &length = $context.flow.get_kex_length($context.connection.get_version(), packet_length) - 4;

type SSH1_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_SMSG_PUBLIC_KEY  -> public_key  : SSH1_PUBLIC_KEY(length);
	SSH_CMSG_SESSION_KEY -> session_key : SSH1_SESSION_KEY(length);
} &let {
	detach : bool=$context.connection.update_state(ENCRYPTED, is_orig);
};

type SSH1_PUBLIC_KEY(length: uint32) = record {
	cookie            : bytestring &length=8;
	server_key        : uint32;
	server_key_exp    : ssh1_mp_int;
	server_key_mod    : ssh1_mp_int;
	host_key          : uint32;
	host_key_exp      : ssh1_mp_int;
	host_key_mod      : ssh1_mp_int;
	flags             : uint32;
	supported_ciphers : uint32;
	supported_auths   : uint32;
} &length=length;

type SSH1_SESSION_KEY(length: uint32) = record {
	cipher      : uint8;
	cookie      : bytestring &length=8;
	session_key : ssh1_mp_int;
	flags       : uint32;
} &length=length;

type ssh1_mp_int = record {
	len : uint16;
	val : bytestring &length=(len+7)/8;
};


## SSH2

type SSH2_Header(is_orig: bool, packet_length: uint32) = record {
	padding_length : uint8;
	msg_type       : uint8;
} &let {
	payload_length : uint32 = packet_length - padding_length - 2;
	detach         : bool = $context.connection.update_state(ENCRYPTED, is_orig) &if(msg_type == MSG_NEWKEYS);
};

type SSH2_Key_Exchange(is_orig: bool, packet_length: uint32) = record {
	header   : SSH2_Header(is_orig, packet_length);
	payload  : SSH2_Message(is_orig, header.msg_type, header.payload_length);
	pad      : bytestring &length=header.padding_length;
} &length=packet_length;

type SSH2_Message(is_orig: bool, msg_type: uint8, length: uint32) = case $context.connection.get_state(is_orig) of {
	KEX_INIT   -> kex        : SSH2_KEXINIT(length, is_orig);
	KEX_DH_GEX -> kex_dh_gex : SSH2_Key_Exchange_DH_GEX_Message(is_orig, msg_type, length);
	KEX_DH     -> kex_dh     : SSH2_Key_Exchange_DH_Message(is_orig, msg_type, length);
	KEX_ECC    -> kex_ecc    : SSH2_Key_Exchange_ECC_Message(is_orig, msg_type, length);
	KEX_GSS    -> kex_gss    : SSH2_Key_Exchange_GSS_Message(is_orig, msg_type, length);
	KEX_RSA    -> kex_rsa    : SSH2_Key_Exchange_RSA_Message(is_orig, msg_type, length);
	default    -> unknown    : bytestring &length=length;
};

type SSH2_KEXINIT(length: uint32, is_orig: bool) = record {
	cookie                                  : bytestring &length=16;
	kex_algorithms                          : ssh_string;
	server_host_key_algorithms              : ssh_string;
	encryption_algorithms_client_to_server  : ssh_string;
	encryption_algorithms_server_to_client  : ssh_string;
	mac_algorithms_client_to_server         : ssh_string;
	mac_algorithms_server_to_client         : ssh_string;
	compression_algorithms_client_to_server : ssh_string;
	compression_algorithms_server_to_client : ssh_string;
	languages_client_to_server              : ssh_string;
	languages_server_to_client              : ssh_string;
	first_kex_packet_follows                : uint8;
	reserved                                : uint32;
} &let {
	proc_kex : bool= $context.connection.update_kex(kex_algorithms.val, is_orig);
} &length=length;

# KEX_DH exchanges

type SSH2_Key_Exchange_DH_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXDH_INIT  -> init   : SSH2_DH_GEX_INIT(length, is_orig);
	SSH_MSG_KEXDH_REPLY -> reply  : SSH2_DH_GEX_REPLY(length);
	default             -> unknown: bytestring &length=length &transient;
};

# KEX_DH_GEX exchanges

type SSH2_Key_Exchange_DH_GEX_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD -> request_old : SSH2_DH_GEX_REQUEST_OLD;
	SSH_MSG_KEX_DH_GEX_REQUEST     -> request     : SSH2_DH_GEX_REQUEST;
	SSH_MSG_KEX_DH_GEX_GROUP       -> group       : SSH2_DH_GEX_GROUP(length);
	SSH_MSG_KEX_DH_GEX_INIT        -> init        : SSH2_DH_GEX_INIT(length, is_orig);
	SSH_MSG_KEX_DH_GEX_REPLY       -> reply       : SSH2_DH_GEX_REPLY(length);
	default                        -> unknown     : bytestring &length=length &transient;
};

type SSH2_DH_GEX_REQUEST = record {
	min : uint32;
	n   : uint32;
	max : uint32;
} &length=12;

type SSH2_DH_GEX_REQUEST_OLD = record {
	n : uint32;
} &length=4;

type SSH2_DH_GEX_GROUP(length: uint32) = record {
	p : ssh_string;
	g : ssh_string;
} &length=length;

type SSH2_DH_GEX_INIT(length: uint32, is_orig: bool) = record {
	e : ssh_string;
} &length=length;

type SSH2_DH_GEX_REPLY(length: uint32) = record {
	k_s       : ssh_string;
	f         : ssh_string;
	signature : ssh_string;
} &length=length;

# KEX_RSA exchanges

type SSH2_Key_Exchange_RSA_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXRSA_PUBKEY -> pubkey : SSH2_RSA_PUBKEY(length);
	SSH_MSG_KEXRSA_SECRET -> secret : SSH2_RSA_SECRET(length, is_orig);
	SSH_MSG_KEXRSA_DONE   -> done   : SSH2_RSA_DONE(length);
};

type SSH2_RSA_PUBKEY(length: uint32) = record {
	k_s : ssh_string;
	k_t : ssh_string;
} &length=length;

type SSH2_RSA_SECRET(length: uint32, is_orig: bool) = record {
	encrypted_payload : ssh_string;
} &length=length;

type SSH2_RSA_DONE(length: uint32) = record {
	signature : ssh_string;
} &length=length;

# KEX_GSS exchanges

type SSH2_Key_Exchange_GSS_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEXGSS_INIT     -> init     : SSH2_GSS_INIT(length, is_orig);
	SSH_MSG_KEXGSS_CONTINUE -> cont     : SSH2_GSS_CONTINUE(length);
	SSH_MSG_KEXGSS_COMPLETE -> complete : SSH2_GSS_COMPLETE(length);
	SSH_MSG_KEXGSS_HOSTKEY  -> hostkey  : SSH2_GSS_HOSTKEY(length);
	SSH_MSG_KEXGSS_ERROR    -> error    : SSH2_GSS_ERROR(length);
	SSH_MSG_KEXGSS_GROUPREQ -> groupreq : SSH2_DH_GEX_REQUEST;
	SSH_MSG_KEXGSS_GROUP    -> group    : SSH2_DH_GEX_GROUP(length);
};

type SSH2_GSS_INIT(length: uint32, is_orig: bool) = record {
	output_token : ssh_string;
	e            : ssh_string;
} &length=length;

type SSH2_GSS_CONTINUE(length: uint32) = record {
	output_token : ssh_string;
} &length=length;

type SSH2_GSS_COMPLETE(length: uint32) = record {
	f                           : ssh_string;
	per_msg_token               : ssh_string;
	have_token                  : uint8;
	parse_token                 : case have_token of {
		0       -> no_token : empty;
		default -> token    : ssh_string;
	};
} &length=length;

type SSH2_GSS_HOSTKEY(length: uint32) = record {
	k_s : ssh_string;
} &length=length;

type SSH2_GSS_ERROR(length: uint32) = record {
	major_status : uint32;
	minor_status : uint32;
	message      : ssh_string;
	language     : ssh_string;
} &length=length;

# KEX_ECDH and KEX_ECMQV exchanges

type SSH2_Key_Exchange_ECC_Message(is_orig: bool, msg_type: uint8, length: uint32) = case msg_type of {
	SSH_MSG_KEX_ECDH_INIT  -> init  : SSH2_ECC_INIT(length, is_orig);
	SSH_MSG_KEX_ECDH_REPLY -> reply : SSH2_ECC_REPLY(length, is_orig);
};

# This deviates from the RFC. SSH_MSG_KEX_ECDH_INIT and
# SSH_MSG_KEX_ECMQV_INIT can be parsed the same way.
type SSH2_ECC_INIT(length: uint32, is_orig: bool) = record {
	q_c : ssh_string;
};

# This deviates from the RFC. SSH_MSG_KEX_ECDH_REPLY and
# SSH_MSG_KEX_ECMQV_REPLY can be parsed the same way.
type SSH2_ECC_REPLY(length: uint32, is_orig: bool) = record {
	k_s       : ssh_string;
	q_s       : ssh_string;
	signature : ssh_string;
};

# Helper types

type ssh_string = record {
	len : uint32;
	val : bytestring &length=len;
};

type ssh_host_key = record {
	len      : uint32;
	key_type : ssh_string;
	key      : ssh_string;
} &length=(len + 4);

## Done with types

refine connection SSH_Conn += {
	%member{
		int state_up_;
		int state_down_;
		int version_;
		int version_client_;
		int version_server_;
		int encrypted_bytes_in_current_segment_;

		bool kex_orig_;
		bool kex_seen_;
		bytestring kex_algs_cache_;
		bytestring kex_algorithm_;
	%}

	%init{
		state_up_   = VERSION_EXCHANGE;
		state_down_ = VERSION_EXCHANGE;
		version_    = UNK;
		version_client_    = UNK;
		version_server_    = UNK;
		encrypted_bytes_in_current_segment_ = 0;

		kex_seen_ = false;
		kex_orig_ = false;
		kex_algs_cache_ = bytestring();
		kex_algorithm_ = bytestring();
	%}

	%cleanup{
		kex_algorithm_.free();
		kex_algs_cache_.free();
	%}

	function clear_encrypted_byte_count_in_current_segment() : bool
		%{
		encrypted_bytes_in_current_segment_ = 0;
		return true;
		%}

	function inc_encrypted_byte_count_in_current_segment() : bool
		%{
		++encrypted_bytes_in_current_segment_;
		return true;
		%}

	function get_encrypted_bytes_in_current_segment() : int
		%{
		return encrypted_bytes_in_current_segment_;
		%}

	function get_state(is_orig: bool) : int
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

	function update_state(s: state, is_orig: bool) : bool
		%{
		if ( is_orig )
			state_up_ = s;
		else
			state_down_ = s;
		return true;
		%}

	function get_version() : int
		%{
		return version_;
		%}

	# If the version is 1.99, that means the client/server is compatible
	# with sshv1 and sshv2. So one says version 2 and the other 1.99
	# the connection will be in version 2 otherwise if its version 1.x and
	# 1.99 the connection be in version 1. See RFC 4253 chapter 5.
	function update_version(v: bytestring, is_orig: bool) : bool
		%{
		if ( v.length() >= 5 )
			{
			if ( v[4] == '2' )
				{
				if ( is_orig )
					version_client_ = SSH2;
				else
					version_server_ = SSH2;
				}
			if ( v[4] == '1' )
				{
				if ( v.length() >= 8 && v[6] == '9' && v[7] == '9' )
					{
					if ( is_orig )
						version_client_ = SSH199;
					else
						version_server_ = SSH199;
					}
				else
					{
					if ( is_orig)
						version_client_ = SSH1;
					else
						version_server_ = SSH1;
					}
				}
			}

		if ( version_server_ == version_client_ )
			{
			// SSH199 vs SSH199 -> 2
			if (version_server_ == SSH199 )
				version_ = SSH2;
			else
				version_ = version_server_;
			}
		// SSH1 vs SSH2 -> Undefined
		// NOLINTBEGIN(bugprone-branch-clone)
		else if ( version_client_ == SSH1 && version_server_ == SSH2 )
			version_ = UNK;
		// SSH2 vs SSH1 -> Undefined
		else if ( version_client_ == SSH2 && version_server_ == SSH1 )
			version_ = UNK;
		// SSH199 vs SSH2 -> 2
		else if ( version_client_ == SSH199 && version_server_ == SSH2 )
			version_ = version_server_;
		// SSH2 vs SSH199 -> 2
		else if ( version_client_ == SSH2 && version_server_ == SSH199 )
			version_ = version_client_;
		// SSH1 vs SSH199 -> 1
		else if ( version_client_ == SSH1 && version_server_ == SSH199 )
			version_ = version_client_;
		// SSH199 vs SSH1 -> 1
		else if ( version_client_ == SSH199 && version_server_ == SSH1 )
			version_ = version_server_;
		// NOLINTEND(bugprone-branch-clone)
		return true;
		%}

	function update_kex_state_if_equal(s: string, to_state: state) : bool
		%{
		if ( std_str(kex_algorithm_).compare(s) == 0 )
			{
			update_state(to_state, true);
			update_state(to_state, false);
			return true;
			}
		return false;
		%}

	function update_kex_state_if_startswith(s: string, to_state: state) : bool
		%{
		if ( (uint) kex_algorithm_.length() < s.length() )
			return false;

		if ( std_str(kex_algorithm_).substr(0, s.length()).compare(s) == 0 )
			{
			update_state(to_state, true);
			update_state(to_state, false);
			return true;
			}
		return false;
		%}

	function update_kex(algs: bytestring, orig: bool) : bool
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

		auto client_list = name_list_to_vector(orig ? algs             : kex_algs_cache_);
		auto server_list = name_list_to_vector(orig ? kex_algs_cache_  : algs);

		for ( unsigned int i = 0; i < client_list->Size(); ++i )
			{
			for ( unsigned int j = 0; j < server_list->Size(); ++j )
				{
				if ( *(client_list->StringAt(i)) == *(server_list->StringAt(j)) )
					{
					kex_algorithm_.free();
					kex_algorithm_.init((const uint8 *) client_list->StringAt(i)->Bytes(),
						client_list->StringAt(i)->Len());

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
					// UNTESTED
					if ( update_kex_state_if_equal("diffie-hellman-group14-sha256", KEX_DH) )
						return true;
					// UNTESTED
					if ( update_kex_state_if_equal("diffie-hellman-group16-sha512", KEX_DH) )
						return true;
					// UNTESTED
					if ( update_kex_state_if_equal("diffie-hellman-group16-sha512", KEX_DH) )
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
					if ( update_kex_state_if_startswith("curve25519-sha256", KEX_ECC) )
						return true;
					// UNTESTED
					if ( update_kex_state_if_startswith("sntrup761x25519-sha512", KEX_ECC) )
						return true;

					zeek_analyzer()->Weird("ssh_unknown_kex_algorithm", c_str(kex_algorithm_));
					return true;

					}
				}
			}

		return true;
		%}

};
