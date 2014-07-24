refine connection SMB_Conn += {
	
	%member{
		// Track read offsets to provide correct 
		// offsets for file manager.
		std::map<uint16,uint64> smb2_read_offsets;
	%}

	function proc_smb2_read_request(h: SMB2_Header, val: SMB2_read_request) : bool
		%{
		if ( smb2_read_request )
			{
			BifEvent::generate_smb2_read_request(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     BuildSMB2HeaderVal(h),
			                                     BuildSMB2GUID(${val.file_id}),
			                                     ${val.offset},
			                                     ${val.read_len});
			}
		
		smb2_read_offsets[${h.message_id}] = ${val.offset};

		return true;
		%}

	function proc_smb2_read_response(h: SMB2_Header, val: SMB2_read_response) : bool
		%{
		if ( ${val.data_len} > 0 )
			{
			uint64 offset = smb2_read_offsets[${h.message_id}];
			smb2_read_offsets.erase(${h.message_id});

			file_mgr->DataIn(${val.data}.begin(), ${val.data_len}, offset,
			                 bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), h->is_orig());
			}

		return true;
		%}

};

type SMB2_read_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	pad                 : uint8;
	reserved            : uint8;
	read_len            : uint32;
	offset              : uint64;
	file_id             : SMB2_guid;
	minimum_count       : uint32;
	channel             : uint32;
	remaining_bytes     : uint32;
	channel_info_offset : uint16;
	channel_info_len    : uint16;

	# These aren't used.
	pad               : padding to channel_info_offset - header.head_length;
	buffer            : bytestring &length = channel_info_len;
} &let {
	proc: bool = $context.connection.proc_smb2_read_request(header, this);
};

type SMB2_read_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	data_offset       : uint16;
	data_len          : uint32;
	data_remaining    : uint32;
	reserved          : uint32;
	pad               : padding to data_offset - header.head_length;
	data              : bytestring &length=data_len;
} &let {
	proc: bool = $context.connection.proc_smb2_read_response(header, this);
};
