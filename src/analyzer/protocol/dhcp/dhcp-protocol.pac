# DHCP Message Type according to RFC 1533.

# Refer to RFC 2131 for op types.
enum OP_type {
	BOOTREQUEST	= 1,
	BOOTREPLY	= 2
};

let MSG_TYPE_OPTION = 53;

type OptionValue(code: uint8, length: uint8) = case code of {
	# This is extended in dhcp-options.pac
	MSG_TYPE_OPTION -> msg_type     : uint8;
	default         -> other        : bytestring &length = length;
};

type OptionValueWrapper(code: uint8) = record {
	length : uint8;
	value  : OptionValue(code, length);
};

type Option = record {
	code   : uint8;
	data   : case code of {
		0, 255  -> none : empty;
		default -> info : OptionValueWrapper(code);
	};
} &let {
	last = (code == 255); # Mark the end of a list of options
};

type DHCP_Message(is_orig: bool) = record {
	op      : uint8;
	htype   : uint8;
	hlen    : uint8;
	hops    : uint8;
	xid     : uint32;
	secs    : uint16;
	flags   : uint16;
	ciaddr  : uint32;
	yiaddr  : uint32;
	siaddr  : uint32;
	giaddr  : uint32;
	chaddr  : bytestring &length = 16;
	sname   : bytestring &length = 64;
	file_n  : bytestring &length = 128;
	# Cookie belongs to options in RFC 2131, but we separate
	# them here for easy parsing.
	cookie  : uint32;
	options : Option[] &until($element.last);
} &let {
	type = $context.flow.get_dhcp_msgtype(options);
} &byteorder = bigendian;

refine flow DHCP_Flow += {
	function get_dhcp_msgtype(options: Option[]): uint8
		%{
		uint8 type = 0;
		for ( auto ptr = options->begin();
		      ptr != options->end() && ! (*ptr)->last(); ++ptr )
			{
			if ( (*ptr)->code() == MSG_TYPE_OPTION )
				{
				type = (*ptr)->info()->value()->msg_type();
				break;
				}
			}

		if ( type == 0 )
			connection()->zeek_analyzer()->AnalyzerViolation("no DHCP message type option");

		return type;
		%}
};
