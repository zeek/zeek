enum smb3_capabilities {
	SMB2_GLOBAL_CAP_DFS                   = 0x00,
	SMB2_GLOBAL_CAP_LEASING               = 0x02,
	SMB2_GLOBAL_CAP_LARGE_MTU             = 0x04,
	SMB2_GLOBAL_CAP_MULTI_CHANNEL         = 0x08,
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES    = 0x10,
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING     = 0x20,
	SMB2_GLOBAL_CAP_ENCRYPTION            = 0x40,
};

enum smb3_context_type {
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES   = 0x0001,
	SMB2_ENCRYPTION_CAPABILITIES          = 0x0002,
	SMB2_COMPRESSION_CAPABILITIES         = 0x0003,
	SMB2_NETNAME_NEGOTIATE_CONTEXT_ID     = 0x0005,
};


refine connection SMB_Conn += {

	function proc_smb2_negotiate_request(h: SMB2_Header, val: SMB2_negotiate_request) : bool
		%{
		if ( smb2_negotiate_request )
			{
			auto dialects = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

			for ( unsigned int i = 0; i < ${val.dialects}->size(); ++i )
				dialects->Assign(i, zeek::val_mgr->Count((*${val.dialects})[i]));

			zeek::BifEvent::enqueue_smb2_negotiate_request(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                         BuildSMB2HeaderVal(h),
			                                         std::move(dialects));
			}

		return true;
		%}

	function proc_smb2_negotiate_response(h: SMB2_Header, val: SMB2_negotiate_response) : bool
		%{
		if ( smb2_negotiate_response )
			{
			auto nr = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::NegotiateResponse);

			nr->Assign(0, ${val.dialect_revision});
			nr->Assign(1, ${val.security_mode});
			nr->Assign(2, BuildSMB2GUID(${val.server_guid}));
			nr->Assign(3, filetime2zeektime(${val.system_time}));
			nr->Assign(4, filetime2zeektime(${val.server_start_time}));
			nr->Assign(5, ${val.negotiate_context_count});

			auto cv = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::SMB2::NegotiateContextValues);

			if ( ${val.dialect_revision} == 0x0311 && ${val.negotiate_context_count} > 0 )
				{
				for ( auto i = 0u; i < ${val.smb3_ncl.list.vals}->size(); ++i )
					cv->Assign(i, BuildSMB2ContextVal(${val.smb3_ncl.list.vals[i].ncv}));

				cv->Assign(${val.smb3_ncl.list.vals}->size(), BuildSMB2ContextVal(${val.smb3_ncl.list.last_val}));
				}

			nr->Assign(6, std::move(cv));

			zeek::BifEvent::enqueue_smb2_negotiate_response(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                                BuildSMB2HeaderVal(h),
			                                                std::move(nr));
			}

		return true;
		%}
};

type SMB3_preauth_integrity_capabilities = record {
	hash_alg_count    	: uint16;
	salt_length     	: uint16;
	hash_alg		: uint16[hash_alg_count];
	salt			: bytestring &length = salt_length;
};

type SMB3_encryption_capabilities = record {
	cipher_count    	: uint16;
	ciphers			: uint16[cipher_count];
};

type SMB3_compression_capabilities = record {
	alg_count : uint16;
	pad:        uint16;
	reserved  : uint32;
	algs      : uint16[alg_count];
};

type SMB3_netname_negotiate_context_id(len: uint16) = record {
	net_name: bytestring &length = len;
};

type SMB3_negotiate_context_value = record {
	context_type    	: uint16;          # specify the type of context
	data_length     	: uint16;          # the length of the data field
	reserved		: uint32;	   # ignored
	data			: case context_type of {
		SMB2_PREAUTH_INTEGRITY_CAPABILITIES   -> preauth_integrity_capabilities : SMB3_preauth_integrity_capabilities;
		SMB2_ENCRYPTION_CAPABILITIES          -> encryption_capabilities        : SMB3_encryption_capabilities;
		SMB2_COMPRESSION_CAPABILITIES         -> compression_capabilities       : SMB3_compression_capabilities;
		SMB2_NETNAME_NEGOTIATE_CONTEXT_ID     -> netname_negotiate_context_id   : SMB3_netname_negotiate_context_id(data_length);
		default                               -> unknown_context_data           : bytestring &length=data_length;
	};
};

type Padded_SMB3_negotiate_context_value = record {
	ncv: SMB3_negotiate_context_value;
	pad: padding align 8;
};

type SMB2_negotiate_request(header: SMB2_Header) = record {
	structure_size    	: uint16;          # client MUST set this to 36
	dialect_count     	: uint16;          # must be > 0
	security_mode     	: uint16;          # there is a list of required modes
	reserved          	: padding[2];      # must be set to 0
	capabilities      	: uint32;          # must be set to 0 if SMB 2.x, otherwise if SMB 3.x one of enum smb2_capabilities
	client_guid       	: SMB2_guid;       # guid if client implements SMB 2.1 dialect, otherwise set to 0
	client_start_time 	: SMB_timestamp;
	dialects          : uint16[dialect_count];
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_request(header, this);
};

type NegotiateContextList(len: uint16) = record {
	vals: Padded_SMB3_negotiate_context_value[len - 1];
	last_val: SMB3_negotiate_context_value;
};

type OptNegotiateContextList(len: uint16) = record {
	opt: case len of {
		0 -> nil: empty;
		default -> list: NegotiateContextList(len);
	};
};

type SMB2_negotiate_response(header: SMB2_Header) = record {
	structure_size            : uint16;
	security_mode             : uint16;
	dialect_revision          : uint16;
	negotiate_context_count   : uint16;	# reserved to 0 if not smb 3.1.1
	server_guid               : SMB2_guid;
	capabilities              : uint32;
	max_transact_size         : uint32;
	max_read_size             : uint32;
	max_write_size            : uint32;
	system_time               : SMB_timestamp;
	server_start_time         : SMB_timestamp;
	security_offset           : uint16;
	security_length           : uint16;
	negotiate_context_offset  : uint32;
	security_blob             : bytestring &length=security_length;
	pad1                      : padding to (dialect_revision == 0x0311 ? negotiate_context_offset - header.head_length : 0);
	negotiate_context_list    : case dialect_revision of {
		0x0311    -> smb3_ncl : OptNegotiateContextList(negotiate_context_count);
		default   -> unknown  : empty;
	};
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_response(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false);

};
