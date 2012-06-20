
type SOCKS_Version(is_orig: bool) = record {
	version: uint8;
	msg:     case version of {
		4       -> socks4_msg:     SOCKS4_Message(is_orig);
		5       -> socks5_msg:     SOCKS5_Message(is_orig);
		default -> socks_msg_fail: SOCKS_Version_Error(version);
	};
};

type SOCKS_Version_Error(version: uint8) = record {
	nothing: empty;
};

# SOCKS5 Implementation
type SOCKS5_Message(is_orig: bool) = case $context.connection.v5_past_authentication() of {
	true  -> msg:  SOCKS5_Real_Message(is_orig);
	false -> auth: SOCKS5_Auth_Negotiation(is_orig);
};

type SOCKS5_Auth_Negotiation(is_orig: bool) = case is_orig of {
	true  -> req:  SOCKS5_Auth_Negotiation_Request;
	false -> rep:  SOCKS5_Auth_Negotiation_Reply;
};

type SOCKS5_Auth_Negotiation_Request = record {
	method_count: uint8;
	methods:      uint8[method_count];
};

type SOCKS5_Auth_Negotiation_Reply = record {
	selected_auth_method: uint8;
} &let {
	past_auth = $context.connection.set_v5_past_authentication();
};

type SOCKS5_Real_Message(is_orig: bool) = case is_orig of {
	true ->  request: SOCKS5_Request;
	false -> reply:   SOCKS5_Reply;
};

type Domain_Name = record {
	len:  uint8;
	name: bytestring &length=len;
} &byteorder = bigendian;

type SOCKS5_Address = record {
	addr_type: uint8;
	addr: case addr_type of {
		1       -> ipv4:        uint32;
		3       -> domain_name: Domain_Name;
		4       -> ipv6:        uint32[4];
		default -> err:         bytestring &restofdata &transient;
	};
} &byteorder = bigendian;

type SOCKS5_Request = record {
	command: uint8;
	reserved: uint8;
	remote_name: SOCKS5_Address;
	port: uint16;
} &byteorder = bigendian;

type SOCKS5_Reply = record {
	reply:     uint8;
	reserved:  uint8;
	bound:     SOCKS5_Address;
	port:      uint16;
} &byteorder = bigendian;


# SOCKS4 Implementation
type SOCKS4_Message(is_orig: bool) = case is_orig of {
	true ->  request: SOCKS4_Request;
	false -> reply:   SOCKS4_Reply;
};

type SOCKS4_Request = record {
	command:  uint8;
	port:     uint16;
	addr:     uint32;
	user:     uint8[] &until($element == 0);
	host:     case v4a of {
		true  -> name:  uint8[] &until($element == 0); # v4a
		false -> empty: uint8[] &length=0;
	} &requires(v4a);
} &byteorder = bigendian &let {
	v4a: bool = (addr <= 0x000000ff);
};

type SOCKS4_Reply = record {
	zero:     uint8;
	status:   uint8;
	port:     uint16;
	addr:     uint32;
} &byteorder = bigendian;


refine connection SOCKS_Conn += {
	%member{
		bool v5_authenticated_;
	%}

	%init{
		v5_authenticated_ = false;
	%}

	function v5_past_authentication(): bool
		%{
		return v5_authenticated_;
		%}

	function set_v5_past_authentication(): bool
		%{
		v5_authenticated_ = true;
		return true;
		%}
};

