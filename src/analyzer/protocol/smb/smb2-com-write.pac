refine connection SMB_Conn += {

	function proc_smb2_write_request(h: SMB2_Header, val: SMB2_write_request) : bool
		%{
		if ( smb2_write_request )
			{
			zeek::BifEvent::enqueue_smb2_write_request(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     BuildSMB2HeaderVal(h),
			                                     BuildSMB2GUID(${val.file_id}),
			                                     ${val.offset},
			                                     ${val.data_len});
			}

		if ( ! ${h.is_pipe} && ${val.data}.length() > 0 )
			{
			zeek::file_mgr->DataIn(${val.data}.begin(), ${val.data_len}, ${val.offset},
			                       bro_analyzer()->GetAnalyzerTag(),
			                       bro_analyzer()->Conn(), h->is_orig());
			}

		return true;
		%}

	function proc_smb2_write_response(h: SMB2_Header, val: SMB2_write_response) : bool
		%{

		if ( smb2_write_response )
			{
			zeek::BifEvent::enqueue_smb2_write_response(bro_analyzer(),
			                                      bro_analyzer()->Conn(),
			                                      BuildSMB2HeaderVal(h),
			                                      ${val.write_count});
			}

		return true;
		%}

};


type SMB2_write_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	data_offset         : uint16;
	data_len            : uint32;
	offset              : uint64;
	file_id             : SMB2_guid;
	channel             : uint32; # ignore
	data_remaining      : uint32;
	channel_info_offset : uint16; # ignore
	channel_info_len    : uint16; # ignore
	flags               : uint32;
	pad                 : padding to data_offset - header.head_length;
	data                : bytestring &length=data_len;
} &let {
	pipe_proc : bool = $context.connection.forward_dce_rpc(data, file_id.persistent+file_id._volatile, true) &if(header.is_pipe);

	proc : bool = $context.connection.proc_smb2_write_request(header, this);
};

type SMB2_write_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	reserved            : uint16;
	write_count         : uint32;
	remaining           : uint32;
	channel_info_offset : uint16;
	channel_info_len    : uint16;
} &let {
	proc : bool = $context.connection.proc_smb2_write_response(header, this);
};
