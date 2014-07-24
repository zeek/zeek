module SMB;

export {
	type StatusCode: record {
		id: string;
		desc: string;
	};

	const statuses: table[count] of StatusCode = {
		[0x00000000] = [$id="SUCCESS", $desc="The operation completed successfully."],
	} &redef &default=function(i: count):StatusCode { local unknown=fmt("unknown-%d", i); return [$id=unknown, $desc=unknown]; };
}

module SMB1;

export {
	const commands: table[count] of string = {
		[0x00] = "CREATE_DIRECTORY",
		[0x01] = "DELETE_DIRECTORY",
		[0x02] = "OPEN",
		[0x03] = "CREATE",
		[0x04] = "CLOSE",
		[0x05] = "FLUSH",
		[0x06] = "DELETE",
		[0x07] = "RENAME",
		[0x08] = "QUERY_INFORMATION",
		[0x09] = "SET_INFORMATION",
		[0x0A] = "READ",
		[0x0B] = "WRITE",
		[0x0C] = "LOCK_BYTE_RANGE",
		[0x0D] = "UNLOCK_BYTE_RANGE",
		[0x0E] = "CREATE_TEMPORARY",
		[0x0F] = "CREATE_NEW",
		[0x10] = "CHECK_DIRECTORY",
		[0x11] = "PROCESS_EXIT",
		[0x12] = "SEEK",
		[0x13] = "LOCK_AND_READ",
		[0x14] = "WRITE_AND_UNLOCK",
		[0x1A] = "READ_RAW",
		[0x1B] = "READ_MPX",
		[0x1C] = "READ_MPX_SECONDARY",
		[0x1D] = "WRITE_RAW",
		[0x1E] = "WRITE_MPX",
		[0x1F] = "WRITE_MPX_SECONDARY",
		[0x20] = "WRITE_COMPLETE",
		[0x21] = "QUERY_SERVER",
		[0x22] = "SET_INFORMATION2",
		[0x23] = "QUERY_INFORMATION2",
		[0x24] = "LOCKING_ANDX",
		[0x25] = "TRANSACTION",
		[0x26] = "TRANSACTION_SECONDARY",
		[0x27] = "IOCTL",
		[0x28] = "IOCTL_SECONDARY",
		[0x29] = "COPY",
		[0x2A] = "MOVE",
		[0x2B] = "ECHO",
		[0x2C] = "WRITE_AND_CLOSE",
		[0x2D] = "OPEN_ANDX",
		[0x2E] = "READ_ANDX",
		[0x2F] = "WRITE_ANDX",
		[0x30] = "NEW_FILE_SIZE",
		[0x31] = "CLOSE_AND_TREE_DISC",
		[0x32] = "TRANSACTION2",
		[0x33] = "TRANSACTION2_SECONDARY",
		[0x34] = "FIND_CLOSE2",
		[0x35] = "FIND_NOTIFY_CLOSE",
		[0x70] = "TREE_CONNECT",
		[0x71] = "TREE_DISCONNECT",
		[0x72] = "NEGOTIATE",
		[0x73] = "SESSION_SETUP_ANDX",
		[0x74] = "LOGOFF_ANDX",
		[0x75] = "TREE_CONNECT_ANDX",
		[0x80] = "QUERY_INFORMATION_DISK",
		[0x81] = "SEARCH",
		[0x82] = "FIND",
		[0x83] = "FIND_UNIQUE",
		[0x84] = "FIND_CLOSE",
		[0xA0] = "NT_TRANSACT",
		[0xA1] = "NT_TRANSACT_SECONDARY",
		[0xA2] = "NT_CREATE_ANDX",
		[0xA4] = "NT_CANCEL",
		[0xA5] = "NT_RENAME",
		[0xC0] = "OPEN_PRINT_FILE",
		[0xC1] = "WRITE_PRINT_FILE",
		[0xC2] = "CLOSE_PRINT_FILE",
		[0xC3] = "GET_PRINT_QUEUE",
		[0xD8] = "READ_BULK",
		[0xD9] = "WRITE_BULK",
		[0xDA] = "WRITE_BULK_DATA",
	} &default=function(i: count):string { return fmt("unknown-%d", i); };
}

module SMB2;

export {
	const commands: table[count] of string = {
		[0]  = "NEGOTIATE_PROTOCOL",
		[1]  = "SESSION_SETUP",
		[2]  = "LOGOFF",
		[3]  = "TREE_CONNECT",
		[4]  = "TREE_DISCONNECT",
		[5]  = "CREATE",
		[6]  = "CLOSE",
		[7]  = "FLUSH",
		[8]  = "READ",
		[9]  = "WRITE",
		[10] = "LOCK",
		[11] = "IOCTL",
		[12] = "CANCEL",
		[13] = "ECHO",
		[14] = "QUERY_DIRECTORY",
		[15] = "CHANGE_NOTIFY",
		[16] = "QUERY_INFO",
		[17] = "SET_INFO",
		[18] = "OPLOCK_BREAK"
	} &default=function(i: count): string { return fmt("unknown-%d", i); };

	const dialects: table[count] of string = {
		[0x0202] = "2.002",
		[0x0210] = "2.1",
		[0x0300] = "3.0",
		[0x0302] = "3.02",
	} &default=function(i: count): string { return fmt("unknown-%d", i); };

	const share_types: table[count] of string = {
		[1] = "DISK",
		[2] = "PIPE",
		[3] = "PRINT",
	} &default=function(i: count): string { return fmt("unknown-%d", i); };
}
