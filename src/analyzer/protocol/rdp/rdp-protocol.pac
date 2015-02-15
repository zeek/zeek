type RDP_PDU(is_orig: bool) = record {
	type:	uint8;
	switch: case type of {
	  0x16 		-> 	ssl_encryption: 	bytestring &restofdata &transient; 	# send to SSL analyzer in the future
	  default 	->	native_encryption:	NativeEncryption;			# TPKT version
	};
} &byteorder=bigendian;

######################################################################
# Native Encryption
######################################################################

type NativeEncryption = record {
	tpkt_reserved:	uint8;
	tpkt_length:	uint16;
        cotp:   	COTP;
};

type COTP = record {
        length: uint8;
        pdu:    uint8;
        switch: case pdu of {
          0xe0    -> cRequest:    ClientRequest;
          0xf0    -> hdr:         COTPHeader;
          default -> data:        bytestring &restofdata &transient;
        };
} &byteorder=littleendian;

type COTPHeader = record {
        tpdu_number:    		uint8;
        application_defined_type:       uint8;  	# this begins a BER encoded multiple octet variant, but can be safely skipped
        application_type:           	uint8;      	# this is value for the BER encoded octet variant above
        switch: case application_type of {
          0x65  -> cHeader:     ClientHeader;     # 0x65 is a client
          0x66  -> sHeader:     ServerHeader;     # 0x66 is a server
          default -> data:      bytestring &restofdata &transient;
        };
} &byteorder=littleendian;

type DataHdr = record {
        type:   uint16;
        length: uint16;
} &byteorder=littleendian;

######################################################################
# Client X.224
######################################################################

type ClientRequest = record {
        destination_reference:  uint16;
        source_reference:       uint16;
        flow_control:   	uint8;
        cookie: 		bytestring &restofdata; # cookie value is a variable length field, so everything is captured
};

######################################################################
# Client MCS
######################################################################

type ClientHeader = record {
	type_length:			padding[3]; # BER encoded long variant, can be safely skipped for now
	calling_domain_selector:	ASN1OctetString;
	called_domain_selector:		ASN1OctetString;
	upward_flag:			ASN1Boolean;
	target_parameters:		ASN1SequenceMeta;
	targ_parameters_pad:		padding[target_parameters.encoding.length];
	minimum_parameters:		ASN1SequenceMeta;
	min_parameters_pad:		padding[minimum_parameters.encoding.length];
	maximum_parameters:		ASN1SequenceMeta;
	max_parameters_pad:		padding[maximum_parameters.encoding.length];
	user_data_length:		uint32; # BER encoded OctetString and long variant, can be safely skipped for now
	gcc_connection_data:    	GCC_Client_ConnectionData;
	gcc_client_create_request:	GCC_Client_CreateRequest;
        core_header:                    DataHdr;
        core_data:      		ClientCore;
	remainder:			bytestring &restofdata &transient; # everything after core_data can be discarded
};

type GCC_Client_ConnectionData = record {
        key_object_length:              uint16;
        key_object:                     uint8[key_object_length];
        connect_data_connect_pdu:       uint16;
} &byteorder=bigendian;

type GCC_Client_CreateRequest = record {
        extension_bit:                  uint8;
        privileges:                     uint8;
        numeric_length:                 uint8;
        numeric:                        uint8;
        termination_method:             uint8;
        number_user_data_sets:          uint8;
        user_data_value_present:        uint8;
        h221_nonstandard_length:        uint8;
        h221_nonstandard_key:           RE/Duca/; # &check would be better here, but it is not implemented
        user_data_value_length:         uint16;
};

type ClientCore = record {
        version_major:          uint16;
        version_minor:          uint16;
        desktop_width:          uint16;
        desktop_height:         uint16;
        color_depth:            uint16;
        sas_sequence:           uint16;
        keyboard_layout:        uint32;
        client_build:           uint32;
        client_name:            bytestring &length=32;
        keyboard_type:          uint32;
        keyboard_sub:           uint32;
        keyboard_function_key:  uint32;
        ime_file_name:          bytestring &length=64;
        post_beta_color_depth:  uint16;
        product_id:             uint16;
        serial_number:          uint32;
        high_color_depth:       uint16;
        supported_color_depth:  uint16;
        early_capability_flags: uint16;
        dig_product_id:         bytestring &length=64;
};

######################################################################
# Server MCS
######################################################################

type ServerHeader = record {
	type_length:                    	padding[3]; 							# BER encoded long variant, can be safely skipped for now
	connect_response_result:		ASN1Enumerated;
	connect_response_called_id:		ASN1Integer;
	connect_response_domain_parameters:	ASN1SequenceMeta;
        domain_parameters_pad:            	padding[connect_response_domain_parameters.encoding.length]; 	# skip this data
	user_data_length:               	uint32; 							# BER encoded OctetString and long variant, can be safely skipped for now
	gcc_connection_data:			GCC_Server_ConnectionData;
	gcc_create_response:			GCC_Server_CreateResponse;
	core_header:				DataHdr;	
        core_data:        			padding[core_header.length - 4]; 				# skip this data
	network_header:				DataHdr;	
        net_data:         			padding[network_header.length - 4]; 				# skip this data 
	security_header:			DataHdr;	
        security_data:    			ServerSecurityData;						
};

type GCC_Server_ConnectionData = record {
	key_object_length:      	uint16;
        key_object:             	uint8[key_object_length];
        connect_data_connect_pdu:       uint8;
} &byteorder=bigendian;

type GCC_Server_CreateResponse = record {
	extension_bit:			uint8;
	node_id:			uint8[2];
	tag_length:			uint8;
	tag:				uint8;
	result:				uint8;
	number_user_data_sets:		uint8;
	user_data_value_present:	uint8;
	h221_nonstandard_length:	uint8;
	h221_nonstandard_key:		RE/McDn/; # &check would be better here, but it is not implemented
	user_data_value_length:		uint16;
};

type ServerCoreData = record {
	version_major:			uint16;
	version_minor:			uint16;
	client_requested_protocols:	uint32;
};

type ServerNetworkData = record {
	mcs_channel_id:	uint16;
	channel_count:	uint16;
};

type ServerSecurityData = record {
        encryption_method:      uint32;
        encryption_level:       uint32;
        server_random_length:   uint32 &byteorder=littleendian;
        server_cert_length:     uint32 &byteorder=littleendian;
        server_random:          bytestring &length=server_random_length;
	server_certificate:	ServerCertificate;
};

type ServerCertificate = record {
        cert_type:           uint8;
        switch: case cert_type of {
          0x01  ->      proprietary:    ServerProprietary;
          0x02  ->      ssl:            SSL; 
        };
} &byteorder=littleendian;

type ServerProprietary = record {
        cert_type:              uint8[3];               # remainder of cert_type value
        signature_algorithm:    uint32;
        key_algorithm:          uint32;
        public_key_blob_type:   uint16;
        public_key_blob_length: uint16;
        public_key_blob:        PublicKeyBlob &length=public_key_blob_length;
        signature_blob_type:    uint16;
        signature_blob_length:  uint16;
        signature_blob:         bytestring &length=signature_blob_length;
};

type PublicKeyBlob = record {
        magic:                  bytestring &length=4;
        key_length:             uint32;
        bit_length:             uint32;
        public_exponent:        uint32;
        modulus:                bytestring &length=key_length;
};

type SSL = record {
	pad1:		padding[11];
	x509_cert:	bytestring &restofdata &transient;	# send to x509 analyzer
};

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
	long_len: bool = len & 0x80;
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

