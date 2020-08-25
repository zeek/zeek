
refine connection SMB_Conn += {

	function proc_smb2_tree_disconnect_request(header: SMB2_Header): bool
		%{
		unset_tree_is_pipe(${header.tree_id});

		if ( smb2_tree_disconnect_request )
			{
			zeek::BifEvent::enqueue_smb2_tree_disconnect_request(zeek_analyzer(),
			                                               zeek_analyzer()->Conn(),
			                                               BuildSMB2HeaderVal(header));
			}

		return true;
		%}

	function proc_smb2_tree_disconnect_response(header: SMB2_Header): bool
		%{
		if ( smb2_tree_disconnect_response )
			{
			zeek::BifEvent::enqueue_smb2_tree_disconnect_response(zeek_analyzer(),
			                                                zeek_analyzer()->Conn(),
			                                                BuildSMB2HeaderVal(header));
			}

		return true;
		%}

};

type SMB2_tree_disconnect_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
} &let {
	proc: bool = $context.connection.proc_smb2_tree_disconnect_request(header);

};

type SMB2_tree_disconnect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
} &let {
	proc: bool = $context.connection.proc_smb2_tree_disconnect_response(header);
};
