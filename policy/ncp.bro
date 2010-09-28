# $Id:$

@load conn-id

module NCP;

global ncp_log = open_log_file("ncp") &redef;

redef capture_filters += {["ncp"] = "tcp port 524"};

export {

const ncp_frame_type_name = {
	[ 0x1111 ] = "NCP_ALLOC_SLOT",
	[ 0x2222 ] = "NCP_REQUEST",
	[ 0x3333 ] = "NCP_REPLY",
	[ 0x5555 ] = "NCP_DEALLOC_SLOT",
	[ 0x7777 ] = "NCP_BURST",
	[ 0x9999 ] = "NCP_ACK",
} &default = function(code: count): string
	{
	return fmt("NCP_UNKNOWN_FRAME_TYPE(%x)", code);
	};

const ncp_function_name = {
	[ 0x01 ] = "NCP_FILE_SET_LOCK",
	[ 0x02 ] = "NCP_FILE_RELEASE_LOCK",
	[ 0x03 ] = "NCP_LOG_FILE",
	[ 0x04 ] = "NCP_LOCK_FILE_SET",
	[ 0x05 ] = "NCP_RELEASE_FILE",
	[ 0x06 ] = "NCP_RELEASE_FILE_SET",
	[ 0x07 ] = "NCP_CLEAR_FILE",
	[ 0x08 ] = "NCP_CLEAR_FILE_SET",
	[ 0x09 ] = "NCP_LOG_LOGICAL_RECORD",
	[ 0x0a ] = "NCP_LOCK_LOGICAL_RECORD_SET",
	[ 0x0b ] = "NCP_CLEAR_LOGICAL_RECORD",
	[ 0x0c ] = "NCP_RELEASE_LOGICAL_RECORD",
	[ 0x0d ] = "NCP_RELEASE_LOGICAL_RECORD_SET",
	[ 0x0e ] = "NCP_CLEAR_LOGICAL_RECORD_SET",
	[ 0x0f ] = "NCP_ALLOC_RESOURCE",
	[ 0x10 ] = "NCP_DEALLOC_RESOURCE",
	[ 0x11 ] = "NCP_PRINT",
	[ 0x15 ] = "NCP_MESSAGE",
	[ 0x16 ] = "NCP_DIRECTORY",
	[ 0x17 ] = "NCP_BINDARY_AND_MISC",
	[ 0x18 ] = "NCP_END_OF_JOB",
	[ 0x19 ] = "NCP_LOGOUT",
	[ 0x1a ] = "NCP_LOG_PHYSICAL_RECORD",
	[ 0x1b ] = "NCP_LOCK_PHYSICAL_RECORD_SET",
	[ 0x1c ] = "NCP_RELEASE_PHYSICAL_RECORD",
	[ 0x1d ] = "NCP_RELEASE_PHYSICAL_RECORD_SET",
	[ 0x1e ] = "NCP_CLEAR_PHYSICAL_RECORD",
	[ 0x1f ] = "NCP_CLEAR_PHYSICAL_RECORD_SET",
	[ 0x20 ] = "NCP_SEMAPHORE",
	[ 0x22 ] = "NCP_TRANSACTION_TRACKING",
	[ 0x23 ] = "NCP_AFP",
	[ 0x42 ] = "NCP_CLOSE_FILE",
	[ 0x47 ] = "NCP_GET_FILE_SIZE",
	[ 0x48 ] = "NCP_READ_FILE",
	[ 0x49 ] = "NCP_WRITE_FILE",
	[ 0x56 ] = "NCP_EXT_ATTR",
	[ 0x57 ] = "NCP_FILE_DIR",
	[ 0x58 ] = "NCP_AUDITING",
	[ 0x5a ] = "NCP_MIGRATION",
	[ 0x60 ] = "NCP_PNW",
	[ 0x61 ] = "NCP_GET_MAX_PACKET_SIZE",
	[ 0x68 ] = "NCP_NDS",
	[ 0x6f ] = "NCP_SEMAPHORE_NEW",
	[ 0x7b ] = "NCP_7B",

	[ 0x5701 ] = "NCP_CREATE_FILE_DIR",
	[ 0x5702 ] = "NCP_INIT_SEARCH",
	[ 0x5703 ] = "NCP_SEARCH_FILE_DIR",
	[ 0x5704 ] = "NCP_RENAME_FILE_DIR",
	[ 0x5706 ] = "NCP_OBTAIN_FILE_DIR_INFO",
	[ 0x5707 ] = "NCP_MODIFY_FILE_DIR_DOS_INFO",
	[ 0x5708 ] = "NCP_DELETE_FILE_DIR",
	[ 0x5709 ] = "NCP_SET_SHORT_DIR_HANDLE",
	[ 0x5714 ] = "NCP_SEARCH_FOR_FILE_DIR_SET",
	[ 0x5718 ] = "NCP_GET_NAME_SPACE_LOADED_LIST",
	[ 0x5742 ] = "NCP_GET_CURRENT_SIZE_OF_FILE",

} &default = function(code: count): string
	{
	return fmt("NCP_UNKNOWN_FUNCTION(%x)", code);
	};

} # export

event ncp_request(c: connection, frame_type: count, length: count, func: count)
	{
	print ncp_log, fmt("%.6f %s NCP request type=%s function=%s",
		network_time(), id_string(c$id),
		ncp_frame_type_name[frame_type],
		ncp_function_name[func]);
	}

event ncp_reply(c: connection, frame_type: count, length: count,
		req_frame: count, req_func: count, completion_code: count)
	{
	}
