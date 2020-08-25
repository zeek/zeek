refine connection SMB_Conn += {

	function proc_smb1_logoff_andx(header: SMB_Header, val: SMB1_logoff_andx): bool
		%{
		if ( smb1_logoff_andx )
			zeek::BifEvent::enqueue_smb1_logoff_andx(zeek_analyzer(), zeek_analyzer()->Conn(), ${val.is_orig});

		return true;
		%}

};

type SMB1_logoff_andx(header: SMB_Header, offset: uint16, is_orig: bool) = record {
	word_count  : uint8;
	andx        : SMB_andx;
	byte_count  : uint16;

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command : SMB_andx_command(header, true, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_logoff_andx(header, this);
};
