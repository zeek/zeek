type SMB2_tree_disconnect_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_tree_disconnect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};
