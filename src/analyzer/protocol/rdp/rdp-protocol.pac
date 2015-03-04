
type TPKT(is_orig: bool) = record {
	version:  uint8;
	reserved: uint8;
	tpkt_len: uint16;

# These data structures are merged together into TPKT
# because there are packets that report incorrect 
# lengths in the tpkt length field.  No clue why.

	cotp:     COTP;
} &byteorder=bigendian &length=tpkt_len;

type COTP = record {
	cotp_len:  uint8;
	pdu:       uint8;
	# Probably should do something with this eventually.
	#cotp_crap: padding[cotp_len-2];
	switch:    case pdu of {
		#0xd0    -> cConfirm: Connect_Confirm;
		0xe0    -> c_request: Client_Request;
		0xf0    -> data:      DT_Data;

		# In case we don't support the PDU we just
		# consume the rest of it and throw it away.
		default -> not_done:  bytestring &restofdata &transient;
	};
} &byteorder=littleendian;

type DT_Data = record {
	tpdu_number:              uint8;
	# multiple octet variant of the ASN.1 type field, should handle this better.
	application_defined_type: uint8;
	application_type:         uint8;

	data: case application_type of {
		0x65    -> client: Client_Header; # 0x65 is a client
		0x66    -> server: Server_Header; # 0x66 is a server
		default -> none:   empty;
	};
} &byteorder=littleendian;

######################################################################
# Data Blocks
######################################################################

type Data_Header = record {
	type:   uint16;
	length: uint16;
} &byteorder=littleendian;

type Data_Block = record {
	header: Data_Header;
	block: case header.type of {
		0xc001  -> client_core:       Client_Core_Data;
		#0xc002  -> client_security:   Client_Security_Data;
		#0xc003  -> client_network:    Client_Network_Data;
		#0xc004  -> client_cluster:    Client_Cluster_Data;
		#0xc005  -> client_monitor:    Client_Monitor_Data;
		#0xc006  -> client_msgchannel: Client_MsgChannel_Data;
		#0xc008  -> client_monitor_ex: Client_MonitorExtended_Data;
		#0xc00A  -> client_multitrans: Client_MultiTransport_Data;

		0x0c01  -> server_core:       Server_Core_Data;
		0x0c02  -> server_security:   Server_Security_Data;
		0x0c03  -> server_network:    Server_Network_Data;
		#0x0c04  -> server_msgchannel: Server_MsgChannel_Data;
		#0x0c08  -> server_multitrans: Server_MultiTransport_Data;

		default -> unhandled:  bytestring &restofdata &transient;
	} &length=header.length-4;
} &byteorder=littleendian;

######################################################################
# Client X.224
######################################################################

type Client_Request = record {
	destination_reference: uint16;
	source_reference:      uint16;
	flow_control:          uint8;
	cookie_mstshash:       RE/Cookie: mstshash\=/;
	cookie_value:          RE/[^\x0d]*/;
};

######################################################################
# Client MCS
######################################################################

type Client_Header = record {
	type_length:               ASN1Integer;
	calling_domain_selector:   ASN1OctetString;
	called_domain_selector:    ASN1OctetString;
	upward_flag:               ASN1Boolean;
	target_parameters:         ASN1SequenceMeta;
	targ_parameters_pad:       padding[target_parameters.encoding.length];
	minimum_parameters:        ASN1SequenceMeta;
	min_parameters_pad:        padding[minimum_parameters.encoding.length];
	maximum_parameters:        ASN1SequenceMeta;
	max_parameters_pad:        padding[maximum_parameters.encoding.length];
	# BER encoded OctetString and long variant, can be safely skipped for now
	user_data_length:          uint32;
	gcc_connection_data:       GCC_Client_Connection_Data;
	gcc_client_create_request: GCC_Client_Create_Request;
	data_blocks:               Data_Block[] &until($input.length() == 0);
};

type GCC_Client_Connection_Data = record {
	key_object_length:        uint16;
	key_object:               uint8[key_object_length];
	connect_data_connect_pdu: uint16;
} &byteorder=bigendian;

type GCC_Client_Create_Request = record {
	extension_bit:           uint8;
	privileges:              uint8;
	numeric_length:          uint8;
	numeric:                 uint8;
	termination_method:      uint8;
	number_user_data_sets:   uint8;
	user_data_value_present: uint8;
	h221_nonstandard_length: uint8;
	h221_nonstandard_key:    RE/Duca/;
	user_data_value_length:  uint16;
} &byteorder=bigendian;

type Client_Core_Data = record {
	version_major:            uint16;
	version_minor:            uint16;
	desktop_width:            uint16;
	desktop_height:           uint16;
	color_depth:              uint16;
	sas_sequence:             uint16;
	keyboard_layout:          uint32;
	client_build:             uint32;
	client_name:              bytestring &length=32;
	keyboard_type:            uint32;
	keyboard_sub:             uint32;
	keyboard_function_key:    uint32;
	ime_file_name:            bytestring &length=64;
	# Everything below here is optional and should be handled better.
	# If some of these fields aren't included it could lead to parse failure.
	post_beta2_color_depth:   uint16;
	client_product_id:        uint16;
	serial_number:            uint32;
	high_color_depth:         uint16;
	supported_color_depths:   uint16;
	early_capability_flags:   uint16;
	dig_product_id:           bytestring &length=64;
	# There are more optional fields here but they are  
	# annoying to optionally parse in binpac.
	# Documented here: https://msdn.microsoft.com/en-us/library/cc240510.aspx
} &let {
	SUPPORT_ERRINFO_PDU:        bool = early_capability_flags & 0x01;
	WANT_32BPP_SESSION:         bool = early_capability_flags & 0x02;
	SUPPORT_STATUSINFO_PDU:     bool = early_capability_flags & 0x04;
	STRONG_ASYMMETRIC_KEYS:     bool = early_capability_flags & 0x08;
	SUPPORT_MONITOR_LAYOUT_PDU: bool = early_capability_flags & 0x40;
	SUPPORT_NETCHAR_AUTODETECT: bool = early_capability_flags & 0x80;
	SUPPORT_DYNVC_GFX_PROTOCOL: bool = early_capability_flags & 0x0100;
	SUPPORT_DYNAMIC_TIME_ZONE:  bool = early_capability_flags & 0x0200;
	SUPPORT_HEARTBEAT_PDU:      bool = early_capability_flags & 0x0400;
} &byteorder=littleendian;

######################################################################
# Server MCS
######################################################################

type Server_Header = record {
	# We don't need this value, but it's ASN.1 integer in definite length
	# so I think we can skip over it.
	type_length:                        uint8[3];
	connect_response_result:            ASN1Enumerated;
	connect_response_called_id:         ASN1Integer;
	connect_response_domain_parameters: ASN1SequenceMeta;
	# Skipping over domain parameters for now.
	domain_parameters:                  padding[connect_response_domain_parameters.encoding.length];
	# I think this is another definite length encoded value.
	user_data_length:                   uint32;
	gcc_connection_data:                GCC_Server_Connection_Data;
	gcc_create_response:                GCC_Server_Create_Response;
	data_blocks:                        Data_Block[] &until($input.length() == 0);
} &byteorder=littleendian;

type GCC_Server_Connection_Data = record {
	key_object_length:        uint16;
	key_object:               uint8[key_object_length];
	connect_data_connect_pdu: uint8;
} &byteorder=bigendian;

type GCC_Server_Create_Response = record {
	extension_bit:           uint8;
	node_id:                 uint16;
	tag_length:              uint8;
	tag:                     uint8;
	result:                  uint8;
	number_user_data_sets:   uint8;
	user_data_value_present: uint8;
	h221_nonstandard_length: uint8;
	h221_nonstandard_key:    RE/McDn/;
	user_data_value_length:  uint16;
} &byteorder=bigendian;

type Server_Core_Data = record {
	version_major:              uint16;
	version_minor:              uint16;
	client_requested_protocols: uint32;
} &byteorder=littleendian;

type Server_Network_Data = record {
	mcs_channel_id: uint16;
	channel_count:  uint16;
} &byteorder=littleendian;

type Server_Security_Data = record {
	encryption_method:      uint32;
	encryption_level:       uint32;
	server_random_length:   uint32;
	server_cert_length:     uint32;
	server_random:          bytestring &length=server_random_length;
	server_certificate:     Server_Certificate &length=server_cert_length;
} &byteorder=littleendian;

type Server_Certificate = record {
	version: uint32;
	switch:  case cert_type of {
		0x01 -> proprietary: Server_Proprietary;
		0x02 -> x509:        X509;
	};
} &let {
	cert_type: uint32 = version & 0x7FFFFFFF;
	permanent_issue: bool = (version & 0x80000000) == 0;
} &byteorder=littleendian;

type Server_Proprietary = record {
	signature_algorithm:    uint32;
	key_algorithm:          uint32;
	public_key_blob_type:   uint16;
	public_key_blob_length: uint16;
	public_key_blob:        Public_Key_Blob &length=public_key_blob_length;
	signature_blob_type:    uint16;
	signature_blob_length:  uint16;
	signature_blob:         bytestring &length=signature_blob_length;
} &byteorder=littleendian;

type Public_Key_Blob = record {
	magic:           bytestring &length=4;
	key_length:      uint32;
	bit_length:      uint32;
	public_exponent: uint32;
	modulus:         bytestring &length=key_length;
} &byteorder=littleendian;

type X509 = record {
	pad1: padding[8];
	cert: bytestring &restofdata;
} &byteorder=littleendian;

######################################################################
# ASN.1 Encodings
######################################################################

type ASN1Encoding = record {
	meta:    ASN1EncodingMeta;
	content: bytestring &length = meta.length;
};

type ASN1EncodingMeta = record {
	tag:      uint8;
	len:      uint8;
	more_len: bytestring &length = long_len ? len & 0x7f : 0;
} &let {
	long_len: bool = (len & 0x80) > 0;
	length:   uint64 = long_len ? binary_to_int64(more_len) : len & 0x7f;
};

type ASN1SequenceMeta = record {
	encoding: ASN1EncodingMeta;
};

type ASN1Integer = record {
	encoding: ASN1Encoding;
};

type ASN1OctetString = record {
	encoding: ASN1Encoding;
};

type ASN1ObjectIdentifier = record {
	encoding: ASN1Encoding;
};

type ASN1Boolean = record {
	encoding: ASN1Encoding;
};

type ASN1Enumerated = record {
	encoding: ASN1Encoding;
};

######################################################################
# ASN.1 Conversion Functions
######################################################################

function binary_to_int64(bs: bytestring): int64
	%{
	int64 rval = 0;
	for ( int i = 0; i < bs.length(); ++i )
		{
		uint64 byte = bs[i];
		rval |= byte << (8 * (bs.length() - (i + 1)));
		}

	return rval;
	%}

