refine connection SMB_Conn += {

	function proc_smb1_tree_disconnect(header: SMB_Header, val: SMB1_tree_disconnect): bool
		%{
		if ( smb1_tree_disconnect )
			zeek::BifEvent::enqueue_smb1_tree_disconnect(zeek_analyzer(),
			                                       zeek_analyzer()->Conn(),
			                                       SMBHeaderVal(header),
			                                       ${val.is_orig});
		return true;
		%}

};

type SMB1_tree_disconnect(header: SMB_Header, is_orig: bool) = record {
	word_count : uint8;

	byte_count : uint16;
} &let {
	proc : bool = $context.connection.proc_smb1_tree_disconnect(header, this);
};
