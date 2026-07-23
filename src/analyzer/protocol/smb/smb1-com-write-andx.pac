refine connection SMB_Conn += {

	function proc_smb1_write_andx_request(h: SMB_Header, val: SMB1_write_andx_request): bool
		%{
		if ( smb1_write_andx_request )
			zeek::BifEvent::enqueue_smb1_write_andx_request(zeek_analyzer(),
			                                          zeek_analyzer()->Conn(),
			                                          SMBHeaderVal(h),
			                                          ${val.file_id},
			                                          ${val.write_offset},
			                                          ${val.data_len});

		if ( ! ${h.is_pipe} && ${val.data}.length() > 0 )
			{
			zeek::file_mgr->DataIn(${val.data}.begin(), ${val.data}.length(),
			                       ${val.write_offset},
			                       zeek_analyzer()->GetAnalyzerTag(),
			                       zeek_analyzer()->Conn(), h->is_orig());
			}

		return true;
		%}

	function proc_smb1_write_andx_response(h: SMB_Header, val: SMB1_write_andx_response): bool
		%{
		if ( smb1_write_andx_response )
			zeek::BifEvent::enqueue_smb1_write_andx_response(zeek_analyzer(),
			                                           zeek_analyzer()->Conn(),
			                                           SMBHeaderVal(h),
			                                           ${val.written_bytes});

		return true;
		%}

};

type SMB1_write_andx_request(header: SMB_Header, offset: uint16, andx_depth: uint8) = record {
	word_count    : uint8;
	andx          : SMB_andx;
	file_id       : uint16;
	offset_low    : uint32;
	timeout       : uint32;
	write_mode    : uint16;
	remaining     : uint16;
	data_len_high : uint16;
	data_len_low  : uint16;
	data_offset   : uint16;
	offset_high_u : case word_count of {
		0x0E      -> offset_high_tmp : uint32;
		default   -> null            : empty;
	};

	byte_count    : uint16;
	pad           : padding to data_offset - SMB_Header_length;
	data          : bytestring &length=data_len;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command    : SMB_andx_command(header, true, offset+offsetof(andx_command), (($context.connection.get_max_andx_depth() > 0 && andx_depth >= $context.connection.get_max_andx_depth()) || andx.offset <= offset) ? 0xff : andx.command, andx_depth + 1);
} &let {
	andx_offset_check : bool = (andx.command != 0xff && andx.offset <= offset) ?
		$context.connection.proc_smb_andx_offset_not_advancing(header) : true;
	andx_depth_check : bool = (andx.command != 0xff && $context.connection.get_max_andx_depth() > 0 && andx_depth >= $context.connection.get_max_andx_depth()) ?
		$context.connection.proc_smb_andx_depth_exceeded(header) : true;
	pipe_proc   : bool   = $context.connection.forward_dce_rpc(data, 0, true) &if(header.is_pipe);

	data_len    : uint32 = (data_len_high << 16) + data_len_low;
	offset_high : uint32 = (word_count == 0x0E) ? offset_high_tmp : 0;
	write_offset: uint64 = (offset_high * 0x10000) + offset_low;
	proc        : bool   = $context.connection.proc_smb1_write_andx_request(header, this);
};

type SMB1_write_andx_response(header: SMB_Header, offset: uint16, andx_depth: uint8) = record {
	word_count   : uint8;
	andx         : SMB_andx;
	written_low  : uint16;
	remaining    : uint16;
	written_high : uint16;
	reserved     : uint16;

	byte_count   : uint16;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command    : SMB_andx_command(header, false, offset+offsetof(andx_command), (($context.connection.get_max_andx_depth() > 0 && andx_depth >= $context.connection.get_max_andx_depth()) || andx.offset <= offset) ? 0xff : andx.command, andx_depth + 1);
} &let {
	andx_offset_check : bool = (andx.command != 0xff && andx.offset <= offset) ?
		$context.connection.proc_smb_andx_offset_not_advancing(header) : true;
	andx_depth_check : bool = (andx.command != 0xff && $context.connection.get_max_andx_depth() > 0 && andx_depth >= $context.connection.get_max_andx_depth()) ?
		$context.connection.proc_smb_andx_depth_exceeded(header) : true;
	written_bytes : uint32 = (written_high << 16) + written_low;
	proc          : bool   = $context.connection.proc_smb1_write_andx_response(header, this);
};
