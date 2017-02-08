refine connection SMB_Conn += {
	# Needs to be implemented.
};

type SMB2_lock = record {
	offset            : uint64;
	len               : uint64;
	flags             : uint32;
};

type SMB2_lock_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	lock_count        : uint16;
	lock_seq          : uint32;
	file_id           : SMB2_guid;
	locks             : SMB2_lock[lock_count];
};

type SMB2_lock_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16; # ignore
};

