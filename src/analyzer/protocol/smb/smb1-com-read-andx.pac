refine connection SMB_Conn += {

	%member{
		// Track read offsets to provide correct 
		// offsets for file manager.
		std::map<uint16,uint64> read_offsets;
	%}

	function proc_smb1_read_andx_request(h: SMB_Header, val: SMB1_read_andx_request): bool
		%{
		if ( smb1_read_andx_request )
			BifEvent::generate_smb1_read_andx_request(bro_analyzer(),
			                                         bro_analyzer()->Conn(),
			                                         BuildHeaderVal(h),
			                                         ${val.file_id},
			                                         ${val.offset},
			                                         ${val.max_count});

		read_offsets[${h.mid}] = ${val.offset};
		return true;
		%}

	function proc_smb1_read_andx_response(h: SMB_Header, val: SMB1_read_andx_response): bool
		%{
		if ( smb1_read_andx_response )
			BifEvent::generate_smb1_read_andx_response(bro_analyzer(),
			                                          bro_analyzer()->Conn(),
			                                          BuildHeaderVal(h),
			                                          ${val.data_len});

		if ( !get_tree_is_pipe(${h.tid}) && ( ${val.data_len} > 0 ) )
			{
			uint64 offset = read_offsets[${h.mid}];
			read_offsets.erase(${h.mid});

			file_mgr->DataIn(${val.data}.begin(), ${val.data_len}, offset,
			                 bro_analyzer()->GetAnalyzerTag(),
			                 bro_analyzer()->Conn(), h->is_orig());
			}

		return true;
		%}

};



type SMB1_read_andx_request(header: SMB_Header) = record {
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
} &let {
	offset_high : uint32 = (word_count == 0x0C) ? offset_high_tmp : 0;
	offset      : uint64 = (offset_high * 0x10000) + offset_low;
	max_count   : uint64 = (max_count_high * 0x10000) + max_count_low;
	proc        : bool   = $context.connection.proc_smb1_read_andx_request(header, this);
} &byteorder=littleendian;

type SMB1_read_andx_response(header: SMB_Header) = record {
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
	is_pipe		  : case $context.connection.get_tree_is_pipe(header.tid) of {
		true  -> pipe_data : SMB_Pipe_message(header, byte_count) &length=data_len;
		default -> data : bytestring &length=data_len;
	} &requires(data_len);
} &let {
	padding_len : uint8  = (header.unicode == 1) ? 1 : 0;
	data_len    : uint32 = (data_len_high << 16) + data_len_low;
	proc        : bool   = $context.connection.proc_smb1_read_andx_response(header, this);
} &byteorder=littleendian;
