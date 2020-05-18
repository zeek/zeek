refine connection SMB_Conn += {

	function proc_smb1_locking_andx_request(header: SMB_Header, val: SMB1_locking_andx_request): bool
		%{
		//printf("locking_andx_request\n");
		return true;
		%}

	function proc_smb1_locking_andx_response(header: SMB_Header, val: SMB1_locking_andx_response): bool
		%{
		//printf("locking_andx_response\n");
		return true;
		%}

};

type LOCKING_ANDX_RANGE32 = record {
	pid         : uint16;
	byte_offset : uint32;
	byte_len    : uint32;
};

type LOCKING_ANDX_RANGE64 = record {
	pid         : uint16;
	pad         : uint16;
	byte_offset : uint64;
	byte_len    : uint64;
};

# http://msdn.microsoft.com/en-us/library/ee442004.aspx
type SMB1_locking_andx_request(header: SMB_Header, offset: uint16) = record {
	word_count            : uint8;
	andx                  : SMB_andx;
	file_id               : uint16;
	type_of_lock          : uint8;
	new_op_lock_level     : uint8;
	timeout               : uint32;
	num_requested_unlocks : uint16;
	num_requested_locks   : uint16;

	bytecount   : uint16;
	unlocks     : case $context.connection.get_offset_len() of {
		32 -> unlocks32 : LOCKING_ANDX_RANGE32[num_requested_unlocks];
		64 -> unlocks64 : LOCKING_ANDX_RANGE64[num_requested_unlocks];
	};
	locks       : case $context.connection.get_offset_len() of {
		32 -> locks32 : LOCKING_ANDX_RANGE32[num_requested_locks];
		64 -> locks64 : LOCKING_ANDX_RANGE64[num_requested_locks];
	};

	extra_byte_parameters : bytestring &transient &length=(andx.offset == 0 || andx.offset >= (offset+offsetof(extra_byte_parameters))+2) ? 0 : (andx.offset-(offset+offsetof(extra_byte_parameters)));

	andx_command          : SMB_andx_command(header, true, offset+offsetof(andx_command), andx.command);
} &let {
	proc : bool = $context.connection.proc_smb1_locking_andx_request(header, this);
};

# http://msdn.microsoft.com/en-us/library/ee441519.aspx
type SMB1_locking_andx_response(header: SMB_Header) = record {
} &let {
	proc : bool = $context.connection.proc_smb1_locking_andx_response(header, this);
};
