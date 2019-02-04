enum smb3_capabilities {
	SMB2_GLOBAL_CAP_DFS			= 0,
	SMB2_GLOBAL_CAP_LEASING 		= 2,
	SMB2_GLOBAL_CAP_LARGE_MTU 		= 4,
	SMB2_GLOBAL_CAP_MULTI_CHANNEL   	= 8,
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES    	= 10,
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING       = 20,
	SMB2_GLOBAL_CAP_ENCRYPTION              = 40,
};

enum smb3_context_type {
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES	= 0x0001,
	SMB2_ENCRYPTION_CAPABILITIES 		= 0x0002,
};


refine connection SMB_Conn += {

	function proc_smb2_negotiate_request(h: SMB2_Header, val: SMB2_negotiate_request) : bool
		%{
		if ( smb2_negotiate_request )
			{
			VectorVal* dialects = new VectorVal(index_vec);
			for ( unsigned int i = 0; i < ${val.dialects}->size(); ++i )
				{
				dialects->Assign(i, val_mgr->GetCount((*${val.dialects})[i]));
				}
			BifEvent::generate_smb2_negotiate_request(bro_analyzer(), bro_analyzer()->Conn(),
			                                          BuildSMB2HeaderVal(h),
			                                          dialects);
			}

		return true;
		%}

	function proc_smb2_negotiate_response(h: SMB2_Header, val: SMB2_negotiate_response) : bool
		%{
		if ( smb2_negotiate_response )
			{
			RecordVal* nr = new RecordVal(BifType::Record::SMB2::NegotiateResponse);

			nr->Assign(0, val_mgr->GetCount(${val.dialect_revision}));
			nr->Assign(1, val_mgr->GetCount(${val.security_mode}));
			nr->Assign(2, BuildSMB2GUID(${val.server_guid}));
			nr->Assign(3, filetime2brotime(${val.system_time}));
			nr->Assign(4, filetime2brotime(${val.server_start_time}));
			nr->Assign(5, val_mgr->GetCount(${val.negotiate_context_count}));

			VectorVal* cv = new VectorVal(BifType::Vector::SMB2::context_values);
			int num_context_values = ${val.negotiate_context_count};
			if (num_context_values > 0)		// check if there are context_values, i.e. SMB v.3.1.1		 			
				for ( int i = 0; i < num_context_values; ++i )
					{
					cv->Assign(i, BuildSMB2ContextVal(${val.smb3_ncl[i]}));		
					}

			nr->Assign(6, cv);	// empty vector if not SMB v.3.1.1
			
			BifEvent::generate_smb2_negotiate_response(bro_analyzer(), bro_analyzer()->Conn(),
			                                           BuildSMB2HeaderVal(h),
			                                           nr);
			}

		return true;
		%}
};

type SMB3_preauth_integrity_capabilities = record {
	hash_alg_count    	: uint16;          
	salt_length     	: uint16;          
	hash_alg		: uint16[hash_alg_count];	   
	salt			: bytestring &length = salt_length;   #TODO is a bytestring ok for this field?
};

type SMB3_encryption_capabilities = record {
	cipher_count    	: uint16;                  
	ciphers			: uint16[cipher_count];	   
};

type SMB3_negotiate_context_values = record {
	context_type    	: uint16;          # specify the type of context
	data_length     	: uint16;          # the length of the data field
	reserved		: uint32;	   # ignored
	data			: case context_type of {   
		SMB2_PREAUTH_INTEGRITY_CAPABILITIES    	-> preauth_integrity_capabilities          : SMB3_preauth_integrity_capabilities;
		SMB2_ENCRYPTION_CAPABILITIES		-> encryption_capabilities	    	   : SMB3_encryption_capabilities;		
	};
	pad			: padding align 4;
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

type SMB2_negotiate_response(header: SMB2_Header) = record {
	structure_size    		: uint16;
	security_mode     		: uint16;
	dialect_revision  		: uint16;
	negotiate_context_count  	: uint16;	# reserved to 0 if not smb 3.1.1
	server_guid       		: SMB2_guid;
	capabilities      		: uint32;
	max_transact_size 		: uint32;
	max_read_size     		: uint32;
	max_write_size    		: uint32;
	system_time       		: SMB_timestamp;
	server_start_time 		: SMB_timestamp;
	security_offset   		: uint16;
	security_length   		: uint16;
	negotiate_context_offset	: uint32;
	pad1              		: padding to security_offset - header.head_length;
	security_blob     		: bytestring &length=security_length;
	pad2				: padding align 8; 	# optional padding
	negotiate_context_list  	: case dialect_revision of {   # check the dialect
		0x0311    	-> smb3_ncl: SMB3_negotiate_context_values[negotiate_context_count];	# if it is v. 3.1.1
		default		-> unknown : empty;			# any other version 
		};
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_response(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false);

};
