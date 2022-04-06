module SMB;

export {
	type StatusCode: record {
		id: string;
		desc: string;
	};

	const statuses: table[count] of StatusCode = {
		[0x00000000] = [$id="SUCCESS", $desc="The operation completed successfully."],
	} &redef &default=function(i: count):StatusCode { local unknown=fmt("unknown-%d", i); return [$id=unknown, $desc=unknown]; };

	## Heuristic detection of named pipes when the pipe
	## mapping isn't seen. This variable is defined in
	## init-bare.zeek.
	redef SMB::pipe_filenames = {
		"spoolss",
		"winreg",
		"samr",
		"srvsvc",
		"netdfs",
		"lsarpc",
		"wkssvc",
		"MsFteWds",
	};

	## The UUIDs used by the various RPC endpoints.
	const rpc_uuids: table[string] of string = {
		["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = "Server Service",
		["6bffd098-a112-3610-9833-46c3f87e345a"] = "Workstation Service",
	} &redef &default=function(i: string):string { return fmt("unknown-uuid-%s", i); };

	## Server service sub commands.
	const srv_cmds: table[count] of string = {
		[8]  = "NetrConnectionEnum",
		[9]  = "NetrFileEnum",
		[10] = "NetrFileGetInfo",
		[11] = "NetrFileClose",
		[12] = "NetrSessionEnum",
		[13] = "NetrSessionDel",
		[14] = "NetrShareAdd",
		[15] = "NetrShareEnum",
		[16] = "NetrShareGetInfo",
		[17] = "NetrShareSetInfo",
		[18] = "NetrShareDel",
		[19] = "NetrShareDelSticky",
		[20] = "NetrShareCheck",
		[21] = "NetrServerGetInfo",
		[22] = "NetrServerSetInfo",
		[23] = "NetrServerDiskEnum",
		[24] = "NetrServerStatisticsGet",
		[25] = "NetrServerTransportAdd",
		[26] = "NetrServerTransportEnum",
		[27] = "NetrServerTransportDel",
		[28] = "NetrRemoteTOD",
		[30] = "NetprPathType",
		[31] = "NetprPathCanonicalize",
		[32] = "NetprPathCompare",
		[33] = "NetprNameValidate",
		[34] = "NetprNameCanonicalize",
		[35] = "NetprNameCompare",
		[36] = "NetrShareEnumSticky",
		[37] = "NetrShareDelStart",
		[38] = "NetrShareDelCommit",
		[39] = "NetrGetFileSecurity",
		[40] = "NetrSetFileSecurity",
		[41] = "NetrServerTransportAddEx",
		[43] = "NetrDfsGetVersion",
		[44] = "NetrDfsCreateLocalPartition",
		[45] = "NetrDfsDeleteLocalPartition",
		[46] = "NetrDfsSetLocalVolumeState",
		[48] = "NetrDfsCreateExitPoint",
		[49] = "NetrDfsDeleteExitPoint",
		[50] = "NetrDfsModifyPrefix",
		[51] = "NetrDfsFixLocalVolume",
		[52] = "NetrDfsManagerReportSiteInfo",
		[53] = "NetrServerTransportDelEx",
		[54] = "NetrServerAliasAdd",
		[55] = "NetrServerAliasEnum",
		[56] = "NetrServerAliasDel",
		[57] = "NetrShareDelEx",
	} &redef &default=function(i: count):string { return fmt("unknown-srv-command-%d", i); };

	## Workstation service sub commands.
	const wksta_cmds: table[count] of string = {
		[0]  = "NetrWkstaGetInfo",
		[1]  = "NetrWkstaSetInfo",
		[2]  = "NetrWkstaUserEnum",
		[5]  = "NetrWkstaTransportEnum",
		[6]  = "NetrWkstaTransportAdd",
		[7]  = "NetrWkstaTransportDel",
		[8]  = "NetrUseAdd",
		[9]  = "NetrUseGetInfo",
		[10] = "NetrUseDel",
		[11] = "NetrUseEnum",
		[13] = "NetrWorkstationStatisticsGet",
		[20] = "NetrGetJoinInformation",
		[22] = "NetrJoinDomain2",
		[23] = "NetrUnjoinDomain2",
		[24] = "NetrRenameMachineInDomain2",
		[25] = "NetrValidateName2",
		[26] = "NetrGetJoinableOUs2",
		[27] = "NetrAddAlternateComputerName",
		[28] = "NetrRemoveAlternateComputerName",
		[29] = "NetrSetPrimaryComputerName",
		[30] = "NetrEnumerateComputerNames",
	} &redef &default=function(i: count):string { return fmt("unknown-wksta-command-%d", i); };

	type rpc_cmd_table: table[count] of string;

	## The subcommands for RPC endpoints.
	const rpc_sub_cmds: table[string] of rpc_cmd_table = {
		["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = srv_cmds,
		["6bffd098-a112-3610-9833-46c3f87e345a"] = wksta_cmds,
	} &redef &default=function(i: string):rpc_cmd_table { return table() &default=function(j: count):string { return fmt("unknown-uuid-%d", j); }; };

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

	const trans2_sub_commands: table[count] of string = {
		[0x00] = "OPEN2",
		[0x01] = "FIND_FIRST2",
		[0x02] = "FIND_NEXT2",
		[0x03] = "QUERY_FS_INFORMATION",
		[0x04] = "SET_FS_INFORMATION",
		[0x05] = "QUERY_PATH_INFORMATION",
		[0x06] = "SET_PATH_INFORMATION",
		[0x07] = "QUERY_FILE_INFORMATION",
		[0x08] = "SET_FILE_INFORMATION",
		[0x09] = "FSCTL",
		[0x0A] = "IOCTL",
		[0x0B] = "FIND_NOTIFY_FIRST",
		[0x0C] = "FIND_NOTIFY_NEXT",
		[0x0D] = "CREATE_DIRECTORY",
		[0x0E] = "SESSION_SETUP",
		[0x10] = "GET_DFS_REFERRAL",
		[0x11] = "REPORT_DFS_INCONSISTENCY",
	} &default=function(i: count):string { return fmt("unknown-trans2-sub-cmd-%d", i); };

	const trans_sub_commands: table[count] of string = {
		[0x01] = "SET_NMPIPE_STATE",
		[0x11] = "RAW_READ_NMPIPE",
		[0x21] = "QUERY_NMPIPE_STATE",
		[0x22] = "QUERY_NMPIPE_INFO",
		[0x23] = "PEEK_NMPIPE",
		[0x26] = "TRANSACT_NMPIPE",
		[0x31] = "RAW_WRITE_NMPIPE",
		[0x36] = "READ_NMPIPE",
		[0x37] = "WRITE_NMPIPE",
		[0x53] = "WAIT_NMPIPE",
		[0x54] = "CALL_NMPIPE",
	} &default=function(i: count):string { return fmt("unknown-trans-sub-cmd-%d", i); };
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
		[0x0202] = "2.0.2",
		[0x0210] = "2.1",
		[0x0300] = "3.0",
		[0x0302] = "3.0.2",
		[0x0311] = "3.1.1",
		[0x02FF] = "2.1+",
	} &default=function(i: count): string { return fmt("unknown-%d", i); };

	const share_types: table[count] of string = {
		[1] = "DISK",
		[2] = "PIPE",
		[3] = "PRINT",
	} &default=function(i: count): string { return fmt("unknown-%d", i); };
}
