refine connection SMB_Conn += {

	function proc_smb2_tree_connect_request(header: SMB2_Header, val: SMB2_tree_connect_request): bool
		%{
		if ( smb2_tree_connect_request )
			zeek::BifEvent::enqueue_smb2_tree_connect_request(zeek_analyzer(),
			                                            zeek_analyzer()->Conn(),
			                                            BuildSMB2HeaderVal(header),
			                                            smb2_string2stringval(${val.path}));

		return true;
		%}

	function proc_smb2_tree_connect_response(header: SMB2_Header, val: SMB2_tree_connect_response): bool
		%{
		if ( ${val.share_type} == SMB2_SHARE_TYPE_PIPE )
			set_tree_is_pipe(${header.tree_id});

		if ( smb2_tree_connect_response )
			{
			auto resp = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::TreeConnectResponse);
			resp->Assign(0, ${val.share_type});

			zeek::BifEvent::enqueue_smb2_tree_connect_response(zeek_analyzer(),
			                                             zeek_analyzer()->Conn(),
			                                             BuildSMB2HeaderVal(header),
			                                             std::move(resp));
			}

		return true;
		%}

};

type SMB2_tree_connect_request(header: SMB2_Header) = record {
	structure_size : uint16;
	reserved       : padding[2];
	path_offset    : uint16;
	path_length    : uint16;

	pad            : padding to path_offset - header.head_length;
	path           : SMB2_string(path_length);
} &let {
	proc: bool = $context.connection.proc_smb2_tree_connect_request(header, this);
};

type SMB2_tree_connect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	share_type        : uint8;
	reserved          : padding[1];
	share_flags       : uint32;
	capabilities      : uint32;
	maximal_access    : uint32;
} &let {
	proc: bool = $context.connection.proc_smb2_tree_connect_response(header, this);
};
