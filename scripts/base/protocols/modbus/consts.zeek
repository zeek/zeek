
module Modbus;

export {
	## Standard defined Modbus function codes.
	const function_codes = {
		[0x01] = "READ_COILS",
		[0x02] = "READ_DISCRETE_INPUTS",
		[0x03] = "READ_HOLDING_REGISTERS",
		[0x04] = "READ_INPUT_REGISTERS",
		[0x05] = "WRITE_SINGLE_COIL",
		[0x06] = "WRITE_SINGLE_REGISTER",
		[0x07] = "READ_EXCEPTION_STATUS",
		[0x08] = "DIAGNOSTICS",
		[0x0B] = "GET_COMM_EVENT_COUNTER",
		[0x0C] = "GET_COMM_EVENT_LOG",
		[0x0F] = "WRITE_MULTIPLE_COILS",
		[0x10] = "WRITE_MULTIPLE_REGISTERS",
		[0x11] = "REPORT_SLAVE_ID",
		[0x14] = "READ_FILE_RECORD",
		[0x15] = "WRITE_FILE_RECORD",
		[0x16] = "MASK_WRITE_REGISTER",
		[0x17] = "READ_WRITE_MULTIPLE_REGISTERS",
		[0x18] = "READ_FIFO_QUEUE",
		[0x2B] = "ENCAP_INTERFACE_TRANSPORT",
		[0x5B] = "OBJECT_MESSAGING", # See https://modbus.org/docs/Object_Messaging_Protocol_ExtensionsVers1.1.doc

		# Machine/vendor/network specific functions
		[0x09] = "PROGRAM_484",
		[0x0A] = "POLL_484",
		[0x0D] = "PROGRAM_584_984",
		[0x0E] = "POLL_584_984",
		[0x12] = "PROGRAM_884_U84",
		[0x13] = "RESET_COMM_LINK_884_U84",
		[0x28] = "PROGRAM_CONCEPT",
		[0x29] = "MULTIPLE_FUNCTION_CODES", # See https://patents.google.com/patent/US20040054829A1/en
		[0x5A] = "PROGRAM_UNITY", # See https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
		[0x7D] = "FIRMWARE_REPLACEMENT",
		[0x7E] = "PROGRAM_584_984_2",
		[0x7F] = "REPORT_LOCAL_ADDRESS",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

	const exception_codes = {
		[0x01] = "ILLEGAL_FUNCTION",
		[0x02] = "ILLEGAL_DATA_ADDRESS",
		[0x03] = "ILLEGAL_DATA_VALUE",
		[0x04] = "SLAVE_DEVICE_FAILURE",
		[0x05] = "ACKNOWLEDGE",
		[0x06] = "SLAVE_DEVICE_BUSY",
		[0x08] = "MEMORY_PARITY_ERROR",
		[0x0A] = "GATEWAY_PATH_UNAVAILABLE",
		[0x0B] = "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}
