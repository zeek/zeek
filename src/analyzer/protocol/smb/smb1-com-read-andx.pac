refine connection SMB_Conn += {

	%member{
		// Track read offsets to provide correct
		// offsets for file manager.
		std::map<uint16,uint64> read_offsets;
	%}

	function proc_smb1_read_andx_request(h: SMB_Header, val: SMB1_read_andx_request): bool
		%{
		if ( smb1_read_andx_request )
			zeek::BifEvent::enqueue_smb1_read_andx_request(zeek_analyzer(),
			                                         zeek_analyzer()->Conn(),
			                                         SMBHeaderVal(h),
			                                         ${val.file_id},
			                                         ${val.read_offset},
			                                         ${val.max_count});

		read_offsets[${h.mid}] = ${val.read_offset};
		return true;
		%}

	function proc_smb1_read_andx_response(h: SMB_Header, val: SMB1_read_andx_response): bool
		%{
		if ( smb1_read_andx_response )
			zeek::BifEvent::enqueue_smb1_read_andx_response(zeek_analyzer(),
			                                          zeek_analyzer()->Conn(),
			                                          SMBHeaderVal(h),
			                                          ${val.data_len});

		if ( ! ${h.is_pipe} && ${val.data_len} > 0 )
			{
			uint64 offset = read_offsets[${h.mid}];
			read_offsets.erase(${h.mid});

			zeek::file_mgr->DataIn(${val.data}.begin(), ${val.data_len}, offset,
			                       zeek_analyzer()->GetAnalyzerTag(),
			                       zeek_analyzer()->Conn(), h->is_orig());
			}

		return true;
		%}

};



type SMB1_read_andx_request(header: SMB_Header, offset: uint16) = record {
	word_count     : uint8;
	andx           : SMB_andx;
	file_id        : uint16;
	offset_low     : uint32;
	max_count_low  : uint16;
	min_count      : uint16;
	max_count_high : uint32;

	remaining      : uint16;
	offset_high_u  : case word_count of {
		0x0C    -> offset_high_tmp : uint32;
		default -> null            : empty;
	};

	byte_count     : uint16;

	extra_byte_parameters : bytestring &transient &length=((andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters))));

	andx_command   : SMB_andx_command(header, true, offset+offsetof(andx_command), andx.command);
} &let {
  offset_high_64 : uint64 = offset_high;
	offset_high : uint32 = (word_count == 0x0C && offset_high_tmp != 0xffffffff) ? offset_high_tmp : 0;
	read_offset : uint64 = ( offset_high_64 * 0x10000) + offset_low &requires(offset_high_64);
	max_count_high_64 : uint64 = max_count_high == 0xffffffff ? 0 : max_count_high;
	max_count   : uint64 = ( max_count_high_64 * 0x10000) + max_count_low &requires(max_count_high_64);
	proc        : bool   = $context.connection.proc_smb1_read_andx_request(header, this);
} &byteorder=littleendian;

type SMB1_read_andx_response(header: SMB_Header, offset: uint16) = record {
	word_count        : uint8;
	andx              : SMB_andx;
	available         : uint16;
	data_compact_mode : uint16;
	reserved1         : uint16;
	data_len_low      : uint16;
	data_offset       : uint16;
	data_len_high     : uint16;
	reserved2         : uint64;

	byte_count        : uint16;
	pad               : padding to data_offset - SMB_Header_length;
	data              : bytestring &length=data_len;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command      : SMB_andx_command(header, false, offset+offsetof(andx_command), andx.command);
} &let {
	pipe_proc   : bool   = $context.connection.forward_dce_rpc(data, 0, false) &if(header.is_pipe);

	padding_len : uint8  = (header.unicode == 1) ? 1 : 0;
	data_len    : uint32 = (data_len_high << 16) + data_len_low;
	proc        : bool   = $context.connection.proc_smb1_read_andx_response(header, this);
} &byteorder=littleendian;
