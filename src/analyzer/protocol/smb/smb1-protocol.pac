%extern{
#include "zeek/file_analysis/Manager.h"
%}

%header{
	zeek::RecordValPtr SMBHeaderVal(SMB_Header* hdr);
%}

%code{
	zeek::RecordValPtr SMBHeaderVal(SMB_Header* hdr)
		{
		auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB1::Header);

		//unsigned int status = 0;
		//
		//try
		//	{
		//	// FIXME: does this work?  We need to catch exceptions :-(
		//	// or use guard functions.
		//	status = ${hdr.status.error} ||
		//	         ${hdr.status.dos_error.error_class} << 24 ||
		//	         ${hdr.status.dos_error.error_class};
		//	}
		//catch ( const binpac::Exception& )
		//	{ // do nothing
		//	}

		r->Assign(0, ${hdr.command});
		r->Assign(1, ${hdr.status});
		r->Assign(2, ${hdr.flags});
		r->Assign(3, ${hdr.flags2});
		r->Assign(4, ${hdr.tid});
		r->Assign(5, ${hdr.pid});
		r->Assign(6, ${hdr.uid});
		r->Assign(7, ${hdr.mid});

		return r;
		}
%}

refine connection SMB_Conn += {
	function join_pid_bits(hi: uint16, lo: uint16): uint32
		%{
		return (static_cast<uint32_t>(hi) << 16) | static_cast<uint32_t>(lo);
		%}

	function proc_smb_message(h: SMB_Header, is_orig: bool): bool
		%{
		if ( smb1_message )
			{
			zeek::BifEvent::enqueue_smb1_message(zeek_analyzer(), zeek_analyzer()->Conn(),
			                                SMBHeaderVal(h),
			                                is_orig);
			}
		return true;
		%}

	function proc_smb_empty_response(header: SMB_Header): bool
		%{
		if ( smb1_empty_response )
			{
			zeek::BifEvent::enqueue_smb1_empty_response(zeek_analyzer(),
			                                      zeek_analyzer()->Conn(),
			                                      SMBHeaderVal(header));
			}
		return true;
		%}

	function proc_smb_no_msg(h: SMB_Header, is_orig: bool): bool
		%{
		if ( ${h.status} == STATUS_SUCCESS )
			{
			if ( smb1_empty_response )
				{
				zeek::BifEvent::enqueue_smb1_empty_response(zeek_analyzer(),
				                                      zeek_analyzer()->Conn(),
				                                      SMBHeaderVal(h));
				}
			}
		else
			{
			if ( smb1_error )
				zeek::BifEvent::enqueue_smb1_error(zeek_analyzer(),
				                             zeek_analyzer()->Conn(),
				                             SMBHeaderVal(h), is_orig);
			}
		return true;
		%}

};

type SMB_dos_error = record {
	error_class : uint8;
	reserved    : uint8;
	error       : uint16;
};

type SMB_error(err_status_type: int) = case err_status_type of {
	0       -> dos_error  : SMB_dos_error;
	default -> error      : uint32;
};

type SMB_andx = record {
	command  : uint8;
	reserved : uint8;
	offset   : uint16;
} &byteorder = littleendian;

type SMB_PDU(is_orig: bool, msg_len: uint32) = record {
	header     : SMB_Header(is_orig);
	message    : case msg_len of {
		# Message length of 35 means that the actual message is
		# only three bytes which means it's an empty response.
		35      -> no_msg : SMB_No_Message(header, is_orig);
		default -> msg    : SMB_Message(header, SMB_Header_length, header.command, is_orig);
	};
};

type SMB_No_Message(header: SMB_Header, is_orig: bool) = record {
	x : bytestring &length=3 &transient;
} &let {
	proc : bool = $context.connection.proc_smb_no_msg(header, is_orig);
};

type SMB_empty_response(header: SMB_Header) = record {
	word_count   : uint8;
	byte_count   : uint16;
} &let {
	proc : bool = $context.connection.proc_smb_empty_response(header);
};

type SMB_Message(header: SMB_Header, offset: uint16, command: uint8, is_orig: bool) = case is_orig of {
	true    ->  request   : SMB_Message_Request(header, offset, command, is_orig);
	false   ->  response  : SMB_Message_Response(header, offset, command, is_orig);
};

type SMB_andx_command(header: SMB_Header, is_orig: bool, offset: uint16, command: uint8) = case command of {
	0xff    -> no_further_commands : empty;
	default -> message             : SMB_Message(header, offset, command, is_orig);
};

type SMB_Message_Request(header: SMB_Header, offset: uint16, command: uint8, is_orig: bool) = case command of {
	# SMB1 Command Extensions
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB1_open_andx_request(header);
	SMB_COM_READ_ANDX                -> read_andx              : SMB1_read_andx_request(header, offset);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB1_write_andx_request(header, offset);
	SMB_COM_TRANSACTION2             -> transaction2           : SMB1_transaction2_request(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB1_negotiate_request(header);
	SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB1_session_setup_andx_request(header, offset);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB1_tree_connect_andx_request(header, offset);
	SMB_COM_NT_TRANSACT              -> nt_transact            : SMB1_nt_transact_request(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB1_nt_create_andx_request(header, offset);

#	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB1_create_directory_request(header);
#	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_request(header);
#	#SMB_COM_OPEN                     -> open                   : SMB_open_request(header);
#	#SMB_COM_CREATE                   -> create                 : SMB_create_request(header);
	SMB_COM_CLOSE                    -> close                  : SMB1_close_request(header);
#	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_request(header);
#	#SMB_COM_DELETE                   -> delete                 : SMB_delete_request(header);
#	#SMB_COM_RENAME                   -> rename                 : SMB_rename_request(header);
	SMB_COM_QUERY_INFORMATION        -> query_information      : SMB1_query_information_request(header);
#	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_request(header);
#	#SMB_COM_READ                     -> read                   : SMB_read_request(header);
#	#SMB_COM_WRITE                    -> write                  : SMB_write_request(header);
#	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_request(header);
#	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_request(header);
#	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_request(header);
#	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_request(header);
	SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB1_check_directory_request(header);
#	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_request(header);
#	#SMB_COM_SEEK                     -> seek                   : SMB_seek_request(header);
#	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_request(header);
#	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_request(header);
#	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_request(header);
#	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_request(header);
#	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_request(header);
#	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_request(header);
#	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_request(header);
#	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_request(header);
#	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_request(header);
#	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_request(header);
#	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_request(header);
#	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_request(header);
	SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB1_locking_andx_request(header, offset);
	SMB_COM_TRANSACTION              -> transaction            : SMB1_transaction_request(header);
	SMB_COM_TRANSACTION_SECONDARY     -> transaction_secondary  : SMB1_transaction_secondary_request(header);
#	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_request(header);
#	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_request(header);
#	#SMB_COM_COPY                     -> copy                   : SMB_copy_request(header);
#	#SMB_COM_MOVE                     -> move                   : SMB_move_request(header);
	SMB_COM_ECHO                     -> echo                   : SMB1_echo_request(header);
#	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_request(header);
#	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_request(header);
#	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_request(header);
	SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB1_transaction2_secondary_request(header);
#	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_request(header);
#	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_request(header);
#	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_request(header);
	SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB1_tree_disconnect(header, is_orig);
	SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB1_logoff_andx(header, offset, is_orig);
#	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_request(header);
#	#SMB_COM_SEARCH                   -> search                 : SMB_search_request(header);
#	#SMB_COM_FIND                     -> find                   : SMB_find_request(header);
#	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_request(header);
#	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_request(header);
#	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_request(header);
	SMB_COM_NT_CANCEL                -> nt_cancel              : SMB1_nt_cancel_request(header);
#	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_request(header);
#	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_request(header);
#	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_request(header);
#	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_request(header);
#	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_request(header);
#	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_request(header);
#	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_request(header);
#	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_request(header);
	default                          -> unknown_msg            : bytestring &restofdata; # TODO: do something different here!
} &byteorder = littleendian;

type SMB_Message_Response(header: SMB_Header, offset: uint16, command: uint8, is_orig: bool) = case command of {
	# SMB1 Command Extensions
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB1_open_andx_response(header, offset);
	SMB_COM_READ_ANDX                -> read_andx              : SMB1_read_andx_response(header, offset);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB1_write_andx_response(header, offset);
	SMB_COM_TRANSACTION2             -> transaction2           : SMB1_transaction2_response(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB1_negotiate_response(header);
	SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB1_session_setup_andx_response(header, offset);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB1_tree_connect_andx_response(header, offset);
	SMB_COM_NT_TRANSACT              -> nt_transact            : SMB1_nt_transact_response(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB1_nt_create_andx_response(header, offset);

#	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB1_create_directory_response(header);
#	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_response(header);
#	#SMB_COM_OPEN                     -> open                   : SMB_open_response(header);
#	#SMB_COM_CREATE                   -> create                 : SMB_create_response(header);
	SMB_COM_CLOSE                    -> close                  : SMB_empty_response(header);
#	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_response(header);
#	#SMB_COM_DELETE                   -> delete                 : SMB_delete_response(header);
#	#SMB_COM_RENAME                   -> rename                 : SMB_rename_response(header);
	SMB_COM_QUERY_INFORMATION        -> query_information      : SMB1_query_information_response(header);
#	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_response(header);
#	#SMB_COM_READ                     -> read                   : SMB_read_response(header);
#	#SMB_COM_WRITE                    -> write                  : SMB_write_response(header);
#	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_response(header);
#	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_response(header);
#	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_response(header);
#	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_response(header);
	SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB1_check_directory_response(header);
#	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_response(header);
#	#SMB_COM_SEEK                     -> seek                   : SMB_seek_response(header);
#	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_response(header);
#	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_response(header);
#	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_response(header);
#	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_response(header);
#	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_response(header);
#	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_response(header);
#	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_response(header);
#	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_response(header);
#	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_response(header);
#	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_response(header);
#	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_response(header);
#	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_response(header);
	SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB1_locking_andx_response(header);
	SMB_COM_TRANSACTION              -> transaction            : SMB1_transaction_response(header);
#	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_response(header);
#	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_response(header);
#	#SMB_COM_COPY                     -> copy                   : SMB_copy_response(header);
#	#SMB_COM_MOVE                     -> move                   : SMB_move_response(header);
	SMB_COM_ECHO                     -> echo                   : SMB1_echo_response(header);
#	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_response(header);
#	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_response(header);
#	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_response(header);
#	#SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB1_transaction2_secondary_response(header);
#	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_response(header);
#	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_response(header);
#	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_response(header);
	SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB1_tree_disconnect(header, is_orig);
	SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB1_logoff_andx(header, offset, is_orig);
#	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_response(header);
#	#SMB_COM_SEARCH                   -> search                 : SMB_search_response(header);
#	#SMB_COM_FIND                     -> find                   : SMB_find_response(header);
#	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_response(header);
#	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_response(header);
#	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_response(header);
	#SMB_COM_NT_CANCEL                -> nt_cancel              : SMB1_nt_cancel_response(header);
#	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_response(header);
#	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_response(header);
#	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_response(header);
#	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_response(header);
#	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_response(header);
#	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_response(header);
#	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_response(header);
#	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_response(header);
	default                          -> unknown_msg            : bytestring &restofdata;
} &byteorder = littleendian;


type SMB_Header(is_orig: bool) = record {
	command           : uint8;
	#status            : SMB_error(err_status_type);
	status            : uint32;
	flags             : uint8;
	flags2            : uint16;
	pid_high          : uint16;
	security_features : uint8[8];
	reserved          : uint16;
	tid               : uint16;
	pid_low           : uint16;
	uid               : uint16;
	mid               : uint16;
} &let {
	err_status_type = (flags2 >> 14) & 1;
	unicode         = (flags2 >> 15) & 1;
	pid: uint32     = $context.connection.join_pid_bits(pid_high, pid_low);
	is_pipe: bool   = $context.connection.get_tree_is_pipe(tid);
	proc : bool     = $context.connection.proc_smb_message(this, is_orig);
} &byteorder=littleendian;

# TODO: compute this as
# let SMB_Header_length = sizeof(SMB_Header);
let SMB_Header_length = 32;


refine connection SMB_Conn += {

	%member{
		int offset_len;
	%}

	%init{
		// This needs to be set to some actual value.
		// TODO: figure out where the hell to get this value from...
		offset_len = 64;
	%}

	function get_offset_len(): int
		%{
		return offset_len;
		%}
};
