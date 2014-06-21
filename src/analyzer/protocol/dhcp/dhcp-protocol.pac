# DHCP Message Type according to RFC 1533.

# Refer to RFC 2131 for op types.
enum OP_type {
	BOOTREQUEST	= 1,
	BOOTREPLY	= 2,
};

# Refer to RFC 1533 for option types.
# The option types are by no means complete.
# Anyone can add a new option type in RFC 1533 to be parsed here.
enum OPTION_type {
	SUBNET_OPTION	 = 1,
	ROUTER_OPTION	 = 3,
	HOST_NAME_OPTION = 12,
	REQ_IP_OPTION	 = 50,
	LEASE_OPTION	 = 51,
	MSG_TYPE_OPTION  = 53,
	SERV_ID_OPTION	 = 54,	# Server address, actually :)
	END_OPTION	 = 255,
};

# Refer to RFC 1533 for message types (with option = 53).
enum DHCP_message_type {
	DHCPDISCOVER	= 1,
	DHCPOFFER	= 2,
	DHCPREQUEST	= 3,
	DHCPDECLINE	= 4,
	DHCPACK		= 5,
	DHCPNAK		= 6,
	DHCPRELEASE	= 7,
	DHCPINFORM	= 8,
};

type Option_Info(code: uint8)  = record {
	length		: uint8;
	value		: case code of {
		SUBNET_OPTION	-> mask	: uint32;
		ROUTER_OPTION	-> router_list : uint32[length/4];
		REQ_IP_OPTION	-> req_addr	: uint32;
		LEASE_OPTION	-> lease	: uint32;
		MSG_TYPE_OPTION	-> msg_type	: uint8;
		SERV_ID_OPTION	-> serv_addr	: uint32;
		HOST_NAME_OPTION-> host_name	: bytestring &length = length;
		default		-> other	: bytestring &length = length;
	};
};

type DHCP_Option = record {
	code		: uint8;
	data		: case code of {
		0, 255	-> none	: empty;
		default	-> info	: Option_Info(code);
	};
} &let {
	last: bool	= (code == 255);   # Mark the end of a list of options
};

#    Message format according to RFC 2131
#
#                           1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     op (1)    |   htype (1)   |    hlen (1)   |     hops (1)    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |				   xid (4)			       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |		  secs (2)	     |		  flags (2)	       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |				  ciaddr (4)			       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |				  yiaddr (4)			       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |				  siaddr (4)			       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |				  giaddr (4)			       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |								       |
#    |				  chaddr (16)			       |
#    /								       /
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |								       |
#    |				   sname (64)			       |
#    /								       /
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |								       |
#    |				   file  (128)			       |
#    /								       /
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |								       |
#    |				 options (variable)		       |
#    /								       /
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type DHCP_Message = record {
	op	: uint8;
	htype	: uint8;
	hlen	: uint8;
	hops	: uint8;
	xid	: uint32;
	secs	: uint16;
	flags	: uint16;
	ciaddr	: uint32;
	yiaddr	: uint32;
	siaddr	: uint32;
	giaddr	: uint32;
	chaddr  : bytestring &length = 16;
	sname	: bytestring &length = 64;
	file	: bytestring &length = 128;

	# Cookie belongs to options in RFC 2131, but we separate
	# them here for easy parsing.
	cookie  : uint32;

	options	: DHCP_Option[] &until($element.last);
} &let {
	type	: uint8 = $context.flow.get_dhcp_msgtype(options);
} &byteorder = bigendian;
