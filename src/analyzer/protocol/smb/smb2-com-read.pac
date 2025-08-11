refine connection SMB_Conn += {

	%member{
		// Track read offsets to provide correct
		// offsets for file manager.
		std::map<uint64,uint64> smb2_read_offsets;
		std::map<uint64,uint64> smb2_read_fids;
	%}

	function get_file_id(message_id: uint64, forget: bool): uint64
		%{
		auto it = smb2_read_fids.find(message_id);

		if ( it == smb2_read_fids.end() )
			return 0;

		uint64 fid = it->second;

		if ( forget )
			smb2_read_fids.erase(it);

		return fid;
		%}

	function proc_smb2_read_request(h: SMB2_Header, val: SMB2_read_request) : bool
		%{
		if ( smb2_read_request )
			{
			zeek::BifEvent::enqueue_smb2_read_request(zeek_analyzer(),
			                                    zeek_analyzer()->Conn(),
			                                    BuildSMB2HeaderVal(h),
			                                    BuildSMB2GUID(${val.file_id}),
			                                    ${val.offset},
			                                    ${val.read_len});
			}

		if ( zeek::BifConst::SMB::max_pending_messages > 0 &&
		     (smb2_read_offsets.size() >= zeek::BifConst::SMB::max_pending_messages ||
		      smb2_read_fids.size() >= zeek::BifConst::SMB::max_pending_messages) )
			{
			if ( smb2_discarded_messages_state )
				zeek::BifEvent::enqueue_smb2_discarded_messages_state(zeek_analyzer(), zeek_analyzer()->Conn(),
				                                                      zeek::make_intrusive<zeek::StringVal>("read"));
			smb2_read_offsets.clear();
			smb2_read_fids.clear();
			}

		smb2_read_offsets[${h.message_id}] = ${val.offset};
		smb2_read_fids[${h.message_id}] = ${val.file_id.persistent} + ${val.file_id._volatile};

		return true;
		%}

	function proc_smb2_read_response(h: SMB2_Header, val: SMB2_read_response) : bool
		%{
		uint64 offset = smb2_read_offsets[${h.message_id}];

		// If a PENDING status was received, keep this around.
		if ( ${h.status} != 0x00000103 )
			smb2_read_offsets.erase(${h.message_id});

		if ( ! ${h.is_pipe} && ${val.data_len} > 0 )
			{
			zeek::file_mgr->DataIn(${val.data}.begin(), ${val.data_len}, offset,
			                       zeek_analyzer()->GetAnalyzerTag(),
			                       zeek_analyzer()->Conn(), h->is_orig());
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
	data_offset       : uint8;
	reserved1         : uint8;
	data_len          : uint32;
	data_remaining    : uint32;
	reserved2         : uint32;
	pad               : padding to data_offset - header.head_length;
	data              : bytestring &length=data_len;
} &let {
	# If a reply is has a pending status, let it remain.
	fid       : uint64 = $context.connection.get_file_id(header.message_id, header.status != 0x00000103);
	pipe_proc : bool   = $context.connection.forward_dce_rpc(data, fid, false) &if(header.is_pipe);

	proc: bool = $context.connection.proc_smb2_read_response(header, this);
};
