type epmapper_lookup_req = record {
	inquiry_type	: uint32;
	# object	: uuid_p_t;
	object		: uint32;
	# interface_id	: rpc_if_id_p_t;
	interface_id	: uint32;
	vers_option	: uint32;
	entry_handle	: context_handle;
};

type epmapper_map_req = record {
};

type epm_uuid 	= record {
	if_uuid		: uuid;
	if_version	: uint16;
} &byteorder = littleendian;

type epm_port 	= uint16 &byteorder = bigendian;
type epm_ip 	= uint32 &byteorder = bigendian;

enum epm_protocol {
	EPM_PROTOCOL_TCP	= 0x07,
	EPM_PROTOCOL_UDP	= 0x08,
	EPM_PROTOCOL_IP		= 0x09,
	EPM_PROTOCOL_UUID	= 0x0d,
};

type epm_lhs_data(length: uint16, protocol: uint8) = case protocol of {
	EPM_PROTOCOL_UUID 	-> uuid : epm_uuid;
	default			-> other: bytestring &length = length;
};

type epm_rhs_data(length: uint16, protocol: uint8) = case protocol of {
	EPM_PROTOCOL_TCP	-> tcp: 	epm_port;
	EPM_PROTOCOL_UDP	-> udp: 	epm_port;
	EPM_PROTOCOL_IP		-> ip: 		epm_ip;
	default			-> other: 	bytestring &length = length;
};

type epm_lhs = record {
	length		: uint16;
	protocol	: uint8;
	data		: epm_lhs_data(length - 1, protocol);
} &byteorder = littleendian;

type epm_rhs(protocol: uint8) = record {
	length		: uint16;
	data		: epm_rhs_data(length, protocol);
} &byteorder = littleendian;

type epm_floor = record {
	lhs		: epm_lhs;
	rhs		: epm_rhs(protocol);
} &let {
	protocol = lhs.protocol;
};

type epm_tower = record {
	num_floors	: uint16;
	floors		: epm_floor[num_floors];
} &byteorder = littleendian;

type epm_twr_p = record {
	# What's the difference between length and tower_length?
	# Why have both?
	ref		: uint32;
	length		: uint32;
	tower_length	: uint32;
	tower		: epm_tower &length = tower_length;
};

type epm_tower_array = record {
	# A lot of questions here ...
	# Why does the array include max_count, offset, and actual_count?
	# Is it because it's a "conformant varying array"?
	# How long should the towers be? actual_count or offset + actual_count?

	max_count	: uint32;
	offset		: uint32;
	actual_count	: uint32;
	towers		: epm_twr_p[actual_count];
};

type epmapper_map_resp = record {
	entry_handle	: context_handle;
	num_towers	: uint32;
	towers		: epm_tower_array;
	return_code	: uint32;
};
