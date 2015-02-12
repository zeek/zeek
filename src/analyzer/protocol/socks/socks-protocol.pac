
type SOCKS_Message(is_orig: bool) = case $context.connection.v5_in_auth_sub_negotiation() of {
	true  -> auth: SOCKS5_Auth_Message(is_orig);
	false -> msg:  SOCKS_Version(is_orig);
};

type SOCKS_Version(is_orig: bool) = record {
	version: uint8;
	msg:     case version of {
		4       -> socks4_msg:      SOCKS4_Message(is_orig);
		5       -> socks5_msg:      SOCKS5_Message(is_orig);
		default -> socks_msg_fail:  SOCKS_Version_Error(version);
	};
};

type SOCKS_Version_Error(version: uint8) = record {
	nothing: empty;
};

# SOCKS5 Implementation
type SOCKS5_Message(is_orig: bool) = case $context.connection.v5_past_authentication() of {
	false -> auth: SOCKS5_Auth_Negotiation(is_orig);
	true  -> msg:  SOCKS5_Real_Message(is_orig);
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
	in_auth_sub_neg = $context.connection.set_v5_in_auth_sub_negotiation(selected_auth_method == 0 || selected_auth_method == 0xff ? false : true);
	past_auth = $context.connection.set_v5_past_authentication();
	set_auth = $context.connection.set_v5_auth_method(selected_auth_method);
};

type SOCKS5_Auth_Message(is_orig: bool) = case is_orig of {
	true  -> req: SOCKS5_Auth_Request;
	false -> rep: SOCKS5_Auth_Reply;
};

type SOCKS5_Auth_Request = case $context.connection.v5_auth_method() of {
	0x02    -> userpass    : SOCKS5_Auth_Request_UserPass;
	default -> unsupported : SOCKS5_Unsupported_Authentication_Method;
};

type SOCKS5_Unsupported_Authentication_Method = record {
	crap: bytestring &restofdata;
};

type SOCKS5_Unsupported_Authentication_Version(version: uint8) = record {
	crap: bytestring &restofdata;
};

type SOCKS5_Auth_Request_UserPass = record {
	version: uint8;
	msg:     case version of {
		1       -> v1:           SOCKS5_Auth_Request_UserPass_v1;
		default -> unsupported:  SOCKS5_Unsupported_Authentication_Version(version);
	};
};

type SOCKS5_Auth_Request_UserPass_v1 = record {
	ulen     : uint8;
	username : bytestring &length=ulen;
	plen     : uint8;
	password : bytestring &length=plen;
};

type SOCKS5_Auth_Reply = case $context.connection.v5_auth_method() of {
	0x02    -> userpass    : SOCKS5_Auth_Reply_UserPass;
	default -> unsupported : SOCKS5_Unsupported_Authentication_Method;
} &let {
	in_auth_sub_neg = $context.connection.set_v5_in_auth_sub_negotiation(false);
};

type SOCKS5_Auth_Reply_UserPass = record {
	version: uint8;
	msg:     case version of {
		1       -> v1:           SOCKS5_Auth_Reply_UserPass_v1;
		default -> unsupported:  SOCKS5_Unsupported_Authentication_Version(version);
	};
};

type SOCKS5_Auth_Reply_UserPass_v1 = record {
	code : uint8;
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
	command     : uint8;
	reserved    : uint8;
	remote_name : SOCKS5_Address;
	port        : uint16;
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
		bool v5_in_auth_sub_negotiation_;
		bool v5_authenticated_;
		uint8 selected_auth_method_;
	%}

	%init{
		v5_in_auth_sub_negotiation_ = false;
		v5_authenticated_ = false;
		selected_auth_method_ = 255;
	%}

	function v5_in_auth_sub_negotiation(): bool
		%{
		return v5_in_auth_sub_negotiation_;
		%}

	function set_v5_in_auth_sub_negotiation(b: bool): bool
		%{
		v5_in_auth_sub_negotiation_ = b;
		return true;
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

	function set_v5_auth_method(method: uint8): bool
		%{
		selected_auth_method_ = method;
		return true;
		%}

	function v5_auth_method(): uint8
		%{
		return selected_auth_method_;
		%}
};

