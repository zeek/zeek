refine connection SMB_Conn += {

	function proc_smb1_open_andx_request(h: SMB_Header, val: SMB1_open_andx_request): bool
		%{
		if ( smb1_open_andx_request )
			BifEvent::generate_smb1_open_andx_request(bro_analyzer(),
			                                          bro_analyzer()->Conn(),
			                                          BuildHeaderVal(h),
			                                          ${val.flags},
			                                          ${val.access_mode},
													  ${val.search_attrs},
													  ${val.file_attrs},
													  ${val.creation_time},
													  ${val.open_mode},
													  ${val.allocation_size},
													  ${val.timeout},
			                                          smb_string2stringval(${val.filename}));

		return true;
		%}

	function proc_smb1_open_andx_response(h: SMB_Header, val: SMB1_open_andx_response): bool
		%{
		if ( smb1_open_andx_response )
			BifEvent::generate_smb1_open_andx_response(bro_analyzer(),
			                                           bro_analyzer()->Conn(),
			                                           BuildHeaderVal(h),
													   ${val.fid},
													   ${val.file_attrs},
													   ${val.last_write_time},
													   ${val.file_data_size},
													   ${val.access_rights},
													   ${val.resource_type},
													   ${val.nm_pipe_status},
													   ${val.open_results});

		return true;
		%}

};



type SMB1_open_andx_request(header: SMB_Header) = record {
	word_count        : uint8;
	andx           	  : SMB_andx;
	flags		   	  : uint16;
	access_mode	   	  : uint16;
	search_attrs   	  : uint16;
	file_attrs	   	  : uint16;
	creation_time  	  : uint32;
	open_mode	   	  : uint16;
	allocation_size   : uint32;
	timeout		      : uint32;
	reserved	   	  : padding[2];
	byte_count	   	  : uint16;
	filename	   	  : SMB_string(header.unicode, offsetof(filename);
} &let {
	proc        : bool   = $context.connection.proc_smb1_open_andx_request(header, this);
} &byteorder=littleendian;

type SMB1_open_andx_response(header: SMB_Header) = record {
	word_count        : uint8;
	andx              : SMB_andx;
	fid				  : uint16;
	file_attrs		  : uint16;
	last_write_time	  : uint32;
	file_data_size	  : uint32;
	access_rights	  : uint16;
	resource_type	  : uint16;
	nm_pipe_status	  : uint16;
	open_results	  : uint16;
	reserved		  : padding[3];
	byte_count		  : uint16;
} &let {
	proc        : bool   = $context.connection.proc_smb1_open_andx_response(header, this);
} &byteorder=littleendian;
