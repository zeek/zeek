@load ./consts

module SMB;

export {
	redef enum Log::ID += { 
		CMD_LOG,
		MAPPING_LOG,
		FILES_LOG
	};
	
	## Abstracted actions for SMB file actions.
	type FileAction: enum {
		FILE_READ,
		FILE_WRITE,
		FILE_OPEN,
		FILE_CLOSE,
		FILE_UNKNOWN,
	};

	## The file actions which are logged.
	const logged_file_actions: set[FileAction] = {
		FILE_OPEN,
		FILE_READ,
		FILE_WRITE,
	} &redef;

	## The server response statuses which are *not* logged.
	const ignored_command_statuses: set[string] = {
		"MORE_PROCESSING_REQUIRED",
	} &redef;
	
	## This record is for the smb_files.log
	type FileInfo: record {
		## Time when the file was first discovered.
		ts				: time    &log;
		## Unique ID of the connection the file was sent over.
		uid				: string  &log;
		## ID of the connection the file was sent over.
		id				: conn_id &log;
		## Unique ID of the file.
		fuid			: string  &log &optional;
		
		## Action this log record represents.
		action			: FileAction  &log &default=FILE_UNKNOWN;
		## Path pulled from the tree this file was transferred to or from.
		path			: string  &log &optional;
		## Filename if one was seen.
		name			: string  &log &optional;
		## Total size of the file.
		size			: count   &log &default=0;
		## Last time this file was modified.
		times			: SMB::MACTimes    &log &optional;
	};

	## This record is for the smb_mapping.log
	type TreeInfo: record {
		## Time when the tree was mapped.
		ts					: time   &log &optional;
		## Unique ID of the connection the tree was mapped over.
		uid					: string  &log;
		## ID of the connection the tree was mapped over.
		id					: conn_id &log;

		## Name of the tree path.
		path				: string &log &optional;
		## The type of resource of the tree (disk share, printer share, named pipe, etc.)
		service				: string &log &optional;
		## File system of the tree.
		native_file_system	: string &log &optional;
		## If this is SMB2, a share type will be included.
		share_type			: string &log &optional;
	};

	## This record is for the smb_cmd.log
	type CmdInfo: record {
		## Timestamp of the command request
		ts				: time &log;
		## Unique ID of the connection the request was sent over
		uid				: string &log;
		## ID of the connection the request was sent over
		id				: conn_id &log;
		
		## The command sent by the client
		command			: string &log;
		## The subcommand sent by the client, if present
		sub_command		: string &log &optional;
		## Command argument sent by the client, if any
		argument		: string &log &optional;
		
		## Server reply to the client's command
		status			: string &log &optional;
		## Round trip time from the request to the response.
		rtt				: interval &log &optional;
		## Version of SMB for the command
		version			: string &log;

		## Authenticated username, if available
		username		: string &log &optional;
		
		## If this is related to a tree, this is the tree
		## that was used for the current command.
		tree			: string &log &optional;
		## The type of tree (disk share, printer share, named pipe, etc.)
		tree_service	: string &log &optional;
		
		## If the command referenced a file, store it here.
		referenced_file	: FileInfo &optional;
		## If the command referenced a tree, store it here.
		referenced_tree	: TreeInfo &optional;
	};

	## This record stores the SMB state of in-flight commands,
	## the file and tree map of the connection.
	type State: record {
		## A reference to the current command.
		current_cmd    : CmdInfo     &optional;
		## A reference to the current file.
		current_file   : FileInfo    &optional;
		## A reference to the current tree.
		current_tree   : TreeInfo    &optional;
		
		## Indexed on MID to map responses to requests.
		pending_cmds: table[count] of CmdInfo   &optional;
		## File map to retrieve file information based on the file ID.
		fid_map     : table[count] of FileInfo  &optional;
		## Tree map to retrieve tree information based on the tree ID.
		tid_map     : table[count] of TreeInfo  &optional;
		## User map to retrieve user name based on the user ID.
		uid_map		: table[count] of string	&optional;
		## Pipe map to retrieve UUID based on the file ID of a pipe.
		pipe_map	: table[count] of string	&optional;
	};
	
	redef record connection += {
		smb_state : State &optional;
	};
	

	## Internal use only
	## Some commands shouldn't be logged by the smb1_message event
	const deferred_logging_cmds: set[string] = {
		"NEGOTIATE",
		"READ_ANDX",
		"SESSION_SETUP_ANDX",
		"TREE_CONNECT_ANDX",
	};
	
	## This is an internally used function.
	const set_current_file: function(smb_state: State, file_id: count) &redef;

	## This is an internally used function.
	const write_file_log: function(f: FileInfo) &redef;
}

redef record FileInfo += {
	## ID referencing this file.
	fid	: count   &optional;

	## Maintain a reference to the file record.
	f	: fa_file &optional;

	## UUID referencing this file if DCE/RPC
	uuid: string &optional;
};

const ports = { 139/tcp, 445/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(CMD_LOG, [$columns=SMB::CmdInfo]);
	Log::create_stream(FILES_LOG, [$columns=SMB::FileInfo]);
	Log::create_stream(MAPPING_LOG, [$columns=SMB::TreeInfo]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SMB, ports);
	}

function set_current_file(smb_state: State, file_id: count)
	{
	if ( file_id !in smb_state$fid_map )
		{
		smb_state$fid_map[file_id] = smb_state$current_cmd$referenced_file;
		smb_state$fid_map[file_id]$fid = file_id;
		}
	
	smb_state$current_file = smb_state$fid_map[file_id];
	}

function write_file_log(f: FileInfo)
	{
	if ( f?$name && 
	     f$name !in pipe_names &&
	     f$action in logged_file_actions )
		{
		Log::write(FILES_LOG, f);
		}
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f$source != "SMB" )
		return;
	
	for ( id in f$conns )
		{
		local c = f$conns[id];
		if ( c?$smb_state && c$smb_state?$current_file)
			{
			write_file_log(c$smb_state$current_file);
			}
		return;
		}
	}