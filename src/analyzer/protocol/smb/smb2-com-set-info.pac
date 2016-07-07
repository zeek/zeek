enum smb2_set_info_type {
	SMB2_0_INFO_FILE       = 0x01,
	SMB2_0_INFO_FILESYSTEM = 0x02,
	SMB2_0_INFO_SECURITY   = 0x03,
	SMB2_0_INFO_QUOTA      = 0x04
};

refine connection SMB_Conn += {

	function proc_smb2_set_info_request(h: SMB2_Header, val: SMB2_set_info_request): bool
		%{
		//if ( smb2_set_info_request && 
		//     ${val.info_type} == SMB2_0_INFO_FILE &&
		//     ${val.file_info_class} == 0x14 )
		//	{
		//	RecordVal* req = new RecordVal(BifType::Record::SMB2::SetInfoRequest);
		//	//req->Assign(0, new Val(${val.eof}, TYPE_COUNT));
		//	req->Assign(0, new Val(0, TYPE_COUNT));
		//	
		//	BifEvent::generate_smb2_set_info_request(bro_analyzer(),
		//	                                         bro_analyzer()->Conn(),
		//	                                         BuildSMB2HeaderVal(h),
		//	                                         req);
		//	}

		return true;
		%}
};

type SMB2_set_info_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	info_type           : uint8;
	file_info_class     : uint8; # this needs a switch below
	buffer_len          : uint32;
	buffer_offset       : uint16;
	reserved            : uint16;
	additional_info     : uint32;
	file_id             : SMB2_guid;

	# These are difficult to deal with.
	#pad                 : padding to (buffer_offset - header.head_length);

	# TODO: a new structure needs to be created for this.
	#eof                 : uint64;
} &let {
	#proc: bool = $context.connection.proc_smb2_set_info_request(header, this);
};

type SMB2_set_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
};
