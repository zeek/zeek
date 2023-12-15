@load ./consts
@load ./const-dos-error
@load ./const-nt-status

module SMB;

export {
	redef enum Log::ID += {
		MAPPING_LOG,
		FILES_LOG
	};

	global log_policy_files: Log::PolicyHook;
	global log_policy_mapping: Log::PolicyHook;

	## Abstracted actions for SMB file actions.
	type Action: enum {
		FILE_READ,
		FILE_WRITE,
		FILE_OPEN,
		FILE_CLOSE,
		FILE_DELETE,
		FILE_RENAME,
		FILE_SET_ATTRIBUTE,

		PIPE_READ,
		PIPE_WRITE,
		PIPE_OPEN,
		PIPE_CLOSE,

		PRINT_READ,
		PRINT_WRITE,
		PRINT_OPEN,
		PRINT_CLOSE,
	};

	## The file actions which are logged.
	option logged_file_actions: set[Action] = {
		FILE_OPEN,
		FILE_RENAME,
		FILE_DELETE,

		PRINT_OPEN,
		PRINT_CLOSE,
	};

	## Whether to reset a connection's SMB script state whenever a
	## :zeek:see:`smb2_discarded_messages_state` event is raised.
	##
	## This setting protects from unbounded script state growth in
	## environments with high capture loss or traffic anomalies.
	option enable_clear_script_state = T;

	## This record is for the smb_files.log
	type FileInfo: record {
		## Time when the file was first discovered.
		ts				: time    &log &default=network_time();
		## Unique ID of the connection the file was sent over.
		uid				: string  &log;
		## ID of the connection the file was sent over.
		id				: conn_id &log;
		## Unique ID of the file.
		fuid			: string  &log &optional;

		## Action this log record represents.
		action			: Action  &log &optional;
		## Path pulled from the tree this file was transferred to or from.
		path			: string  &log &optional;
		## Filename if one was seen.
		name			: string  &log &optional;
		## Total size of the file.
		size			: count   &log &default=0;
		## If the rename action was seen, this will be
		## the file's previous name.
		prev_name		: string  &log &optional;
		## Last time this file was modified.
		times			: SMB::MACTimes &log &optional;
	};

	## This record is for the smb_mapping.log
	type TreeInfo: record {
		## Time when the tree was mapped.
		ts                  : time   &log &default=network_time();
		## Unique ID of the connection the tree was mapped over.
		uid                 : string  &log;
		## ID of the connection the tree was mapped over.
		id                  : conn_id &log;

		## Name of the tree path.
		path                : string &log &optional;
		## The type of resource of the tree (disk share, printer share, named pipe, etc.).
		service             : string &log &optional;
		## File system of the tree.
		native_file_system  : string &log &optional;
		## If this is SMB2, a share type will be included.  For SMB1,
		## the type of share will be deduced and included as well.
		share_type          : string &log &default="DISK";
	};

	## This record is for the smb_cmd.log
	type CmdInfo: record {
		## Timestamp of the command request.
		ts				: time &log &default=network_time();
		## Unique ID of the connection the request was sent over.
		uid				: string &log;
		## ID of the connection the request was sent over.
		id				: conn_id &log;

		## The command sent by the client.
		command			: string &log;
		## The subcommand sent by the client, if present.
		sub_command		: string &log &optional;
		## Command argument sent by the client, if any.
		argument		: string &log &optional;

		## Server reply to the client's command.
		status			: string &log &optional;
		## Round trip time from the request to the response.
		rtt				: interval &log &optional;
		## Version of SMB for the command.
		version			: string &log;

		## Authenticated username, if available.
		username		: string &log &optional;

		## If this is related to a tree, this is the tree
		## that was used for the current command.
		tree			: string &log &optional;
		## The type of tree (disk share, printer share, named pipe, etc.).
		tree_service	: string &log &optional;

		## If the command referenced a file, store it here.
		referenced_file	: FileInfo &log &optional;
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
		pending_cmds : table[count] of CmdInfo   &optional;
		## File map to retrieve file information based on the file ID.
		fid_map      : table[count] of FileInfo  &optional;
		## Tree map to retrieve tree information based on the tree ID.
		tid_map      : table[count] of TreeInfo  &optional;
		## Pipe map to retrieve UUID based on the file ID of a pipe.
		pipe_map     : table[count] of string    &optional;

		## A set of recent files to avoid logging the same
		## files over and over in the smb files log.
		## This only applies to files seen in a single connection.
		recent_files : set[string] &default=set() &read_expire=3min;
	};

	## Everything below here is used internally in the SMB scripts.

	redef record connection += {
		smb_state : State &optional;
	};

	## This is an internally used function.
	const set_current_file: function(smb_state: State, file_id: count) &redef;

	## This is an internally used function.
	const write_file_log: function(state: State) &redef;
}

redef record FileInfo += {
	## ID referencing this file.
	fid  : count   &optional;

	## UUID referencing this file if DCE/RPC.
	uuid : string &optional;
};

const ports = { 139/tcp, 445/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(SMB::FILES_LOG, [$columns=SMB::FileInfo, $path="smb_files", $policy=log_policy_files]);
	Log::create_stream(SMB::MAPPING_LOG, [$columns=SMB::TreeInfo, $path="smb_mapping", $policy=log_policy_mapping]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SMB, ports);
	}

function set_current_file(smb_state: State, file_id: count)
	{
	if ( file_id !in smb_state$fid_map )
		{
		smb_state$fid_map[file_id] = smb_state$current_cmd$referenced_file;
		smb_state$fid_map[file_id]$fid = file_id;
		}

	smb_state$current_cmd$referenced_file = smb_state$fid_map[file_id];
	smb_state$current_file = smb_state$current_cmd$referenced_file;
	}

function write_file_log(state: State)
	{
	local f = state$current_file;
	if ( f?$name &&
	     f$action in logged_file_actions )
		{
		# Everything in this if statement is to avoid overlogging
		# of the same data from a single connection based on recently
		# seen files in the SMB::State $recent_files field.
		if ( f?$times )
			{
			local file_ident = cat(f$action,
			                       f?$fuid ? f$fuid : "",
			                       f?$name ? f$name : "",
			                       f?$path ? f$path : "",
			                       f$size,
			                       f$times);
			if ( file_ident in state$recent_files )
				{
				# We've already seen this file and don't want to log it again.
				return;
				}
			else
				add state$recent_files[file_ident];
			}

		Log::write(FILES_LOG, f);
		}
	}

event smb_pipe_connect_heuristic(c: connection) &priority=5
	{
	c$smb_state$current_tree$path = "<unknown>";
	c$smb_state$current_tree$share_type = "PIPE";
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f$source != "SMB" )
		return;

	for ( _, c in f$conns )
		{
		if ( c?$smb_state && c$smb_state?$current_file)
			{
			write_file_log(c$smb_state);
			}
		return;
		}
	}
