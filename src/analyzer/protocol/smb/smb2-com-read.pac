refine connection SMB_Conn += {

	%member{
		// Track read offsets to provide correct
		// offsets for file manager.
		std::map<uint16,uint64> smb2_read_offsets;
		std::map<uint64,uint64> smb2_read_fids;
	%}

	function get_file_id(message_id: uint64): uint64
		%{
		if ( smb2_read_fids.count(message_id) == 0 )
			return 0;
		else
			{
			uint64 fid = smb2_read_fids[message_id];
			smb2_read_fids.erase(message_id);
			return fid;
			}
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
		smb2_read_fids[${h.message_id}] = ${val.file_id.persistent} + ${val.file_id._volatile};

		return true;
		%}

	function proc_smb2_read_response(h: SMB2_Header, val: SMB2_read_response) : bool
		%{
		uint64 offset = smb2_read_offsets[${h.message_id}];
		smb2_read_offsets.erase(${h.message_id});

		if ( ! ${h.is_pipe} && ${val.data_len} > 0 )
			{
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
	fid       : uint64 = $context.connection.get_file_id(header.message_id);
	pipe_proc : bool   = $context.connection.forward_dce_rpc(data, fid, false) &if(header.is_pipe);

	proc: bool = $context.connection.proc_smb2_read_response(header, this);
};
