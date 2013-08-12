
module DNP3;

export {
	## Standard defined Modbus function codes.
	const function_codes = {
		# Requests.
		[0x00] = "CONFIRM",
		[0x01] = "READ",
		[0x02] = "WRITE",
		[0x03] = "SELECT",
		[0x04] = "OPERATE",
		[0x05] = "DIRECT_OPERATE",
		[0x06] = "DIRECT_OPERATE_NR",
		[0x07] = "IMMED_FREEZE",
		[0x08] = "IMMED_FREEZE_NR",
		[0x09] = "FREEZE_CLEAR",
		[0x0a] = "FREEZE_CLEAR_NR",
		[0x0b] = "FREEZE_AT_TIME",
		[0x0c] = "FREEZE_AT_TIME_NR",
		[0x0d] = "COLD_RESTART",
		[0x0e] = "WARM_RESTART",
		[0x0f] = "INITIALIZE_DATA",
		[0x10] = "INITIALIZE_APPL",
		[0x11] = "START_APPL",
		[0x12] = "STOP_APPL",
		[0x13] = "SAVE_CONFIG",
		[0x14] = "ENABLE_UNSOLICITED",
		[0x15] = "DISABLE_UNSOLICITED",
		[0x16] = "ASSIGN_CLASS",
		[0x17] = "DELAY_MEASURE",
		[0x18] = "RECORD_CURRENT_TIME",
		[0x19] = "OPEN_FILE",
		[0x1a] = "CLOSE_FILE",
		[0x1b] = "DELETE_FILE",
		[0x1c] = "GET_FILE_INFO",
		[0x1d] = "AUTHENTICATE_FILE",
		[0x1e] = "ABORT_FILE",
		[0x1f] = "ACTIVATE_CONFIG",
		[0x20] = "AUTHENTICATE_REQ",
		[0x21] = "AUTHENTICATE_ERR",

		# Responses.
		[0x81] = "RESPONSE",
		[0x82] = "UNSOLICITED_RESPONSE",
		[0x83] = "AUTHENTICATE_RESP",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}

