refine connection SMB_Conn += {

	function proc_smb1_logoff_andx(header: SMB_Header, val: SMB1_logoff_andx): bool
		%{
		if ( smb1_logoff_andx )
			zeek::BifEvent::enqueue_smb1_logoff_andx(zeek_analyzer(), zeek_analyzer()->Conn(), ${val.is_orig});

		return true;
		%}

};

type SMB1_logoff_andx(header: SMB_Header, offset: uint16, is_orig: bool, andx_depth: uint8) = record {
	word_count  : uint8;
	andx        : SMB_andx;
	byte_count  : uint16;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command : SMB_andx_command(header, true, offset+offsetof(andx_command), $context.connection.adjust_andx_command(andx_depth, offset, andx.offset, andx.command), andx_depth + 1);
} &let {
	andx_offset_check : bool = $context.connection.check_offset_advancing(andx.command, offset, andx.offset);
	andx_depth_check : bool = $context.connection.check_andx_depth(andx_depth, andx.command);
	proc : bool = $context.connection.proc_smb1_logoff_andx(header, this);
};
