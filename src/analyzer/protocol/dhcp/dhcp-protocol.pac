# DHCP Message Type according to RFC 1533.

# Refer to RFC 2131 for op types.
enum OP_type {
	BOOTREQUEST	= 1,
	BOOTREPLY	= 2
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
	SERV_ID_OPTION	 = 54, # Server address, actually :)
	PAR_REQ_LIST	 = 55, # Parameters Request List - NEW
	REN_TIME_OPTION	 = 58, # Renewal time - NEW
	REB_TIME_OPTION  = 59, # Rebinding time - NEW
	CLIENT_ID_OPTION = 61, # Client Identifier - NEW
	RELAY_AGENT_INF  = 82, # Relay Agent Information - NEW
	END_OPTION	 = 255
};

enum DHCP_message_type {
	DHCPDISCOVER		= 1,
	DHCPOFFER		= 2,
	DHCPREQUEST		= 3,
	DHCPDECLINE		= 4,
	DHCPACK			= 5,
	DHCPNAK			= 6,
	DHCPRELEASE		= 7,
	DHCPINFORM		= 8,
	DHCPFORCERENEW  	= 9,	# RFC 2132
	DHCPLEASEQUERY 		= 10,	# RFC 4388
	DHCPLEASEUNASSIGNED 	= 11, 	# RFC 4388
	DHCPLEASEUNKNOWN	= 12,	# RFC 4388
	DHCPLEASEACTIVE		= 13	# RFC 4388
};

type Relay_Agent_SubOption(tot_len: uint8) = record {
	code	: uint8;
	length	: uint8;
	value	: bytestring &length = length;
} &let {
	sum_len: uint8 = $context.flow.get_dhcp_sumlen(length + 2);
	last: bool = (sum_len == tot_len);
};

type Client_Identifier(length: uint8) = record {
	hwtype	: uint8;
	hwaddr	: bytestring &length = length -1;
};

enum DHCP_hardware_type
{
	ETHERNET = 1,
	EXPERIMENTAL_ETHERNET = 2
};

type Option_Info(code: uint8)  = record {
	length		: uint8;
	value		: case code of {
		SUBNET_OPTION	 -> mask	 : uint32;
		ROUTER_OPTION	 -> router_list  : uint32[length/4];
		REQ_IP_OPTION	 -> req_addr	 : uint32;
		LEASE_OPTION	 -> lease	 : uint32;
		MSG_TYPE_OPTION	 -> msg_type	 : uint8;
		SERV_ID_OPTION	 -> serv_addr	 : uint32;
		HOST_NAME_OPTION -> host_name	 : bytestring &length = length;
		PAR_REQ_LIST	 -> par_req_list : uint8[length];
		REB_TIME_OPTION	 -> reb_time	 : uint32;
		REN_TIME_OPTION  -> ren_time	 : uint32;
		CLIENT_ID_OPTION -> client_id	 : Client_Identifier(length);
		RELAY_AGENT_INF  -> relay_agent_inf : Relay_Agent_SubOption(length)[] &until($element.last);
		default		 -> other	 : bytestring &length = length;
	};
};

type DHCP_Option = record {
	code		: uint8;
	data		: case code of {
		0, 255	-> none	: empty;
		default	-> info	: Option_Info(code);
	};
} &let {
	last: bool	= (code == END_OPTION);   # Mark the end of a list of options
};

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
