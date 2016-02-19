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

	const logged_file_actions: set[FileAction] = {
		FILE_OPEN,
		FILE_READ,
		FILE_WRITE,
	};

	## These are files names that are used for special 
	## cases by the file system and would not be 
	## considered "normal" files.
	const pipe_names: set[string] = {
		"\\netdfs",
		"\\spoolss",
		"\\NETLOGON",
		"\\winreg",
		"\\lsarpc",
		"\\samr",
		"\\srvsvc",
		"srvsvc",
		"MsFteWds",
		"\\wkssvc",
	};

	type FileInfo: record {
		## Time when the file was first discovered.
		ts             : time    &log;
		uid            : string  &log;
		id             : conn_id &log;
		fuid           : string  &log;

		## Action this log record represents.
		action         : FileAction  &log &default=FILE_UNKNOWN;

		## Path pulled from the tree this file was transferred to or from.
		path           : string  &log &optional;
		## Filename if one was seen.
		name           : string  &log &optional;

		## Total size of the file.
		size           : count   &log &default=0;
		## Last time this file was modified.
		times          : SMB::MACTimes    &log &optional;
	};
	
	type TreeInfo: record {
		## Time when the tree was mapped.
		ts                 : time   &log &optional;

		uid                : string  &log;
		id                 : conn_id &log;

		## Name of the tree path.
		path               : string &log &optional;
		service            : string &log &optional;
		native_file_system : string &log &optional;

		## If this is SMB2, a share type will be included.
		share_type         : string &log &optional;
	};
	
	type CmdInfo: record {
		## The command.
		command              : string   &optional;

		## If the command referenced a file, store it here.
		referenced_file      : FileInfo &optional;
		## If the command referenced a tree, store it here.
		referenced_tree      : TreeInfo &optional;
	};
	
	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;

		## Version of SMB for the command.
		version: string &log;

		## Command sent by the client.
		command: string &log &optional;

		## Server reply to the client's command
		status: string &log &optional;
		
		## If this is related to a tree, this is the tree
		## that was used for the current command. 
		tree: string &log &optional;

		## The negotiated dialect for the connection.
		dialect: string &log &optional;

		## Round trip time from the request to the response.
		rtt: interval &log &optional;

		## A reference to the current command.
		current_cmd    : CmdInfo     &optional;

		## A reference to the current file.
		current_file   : FileInfo    &optional;
		
		## A reference to the current tree.
		current_tree   : TreeInfo    &optional;
		
		## Indexed on MID to map responses to requests.
		pending_cmds   : table[count] of CmdInfo    &optional;
		## File map to retrieve file information based on the file ID.
		fid_map        : table[count] of FileInfo   &optional;
		## Tree map to retrieve tree information based on the tree ID.
		tid_map        : table[count] of TreeInfo   &optional;
	};
	
	redef record connection += {
		smb : Info &optional;
	};

	## Optionally write out the SMB commands log.  This is 
	## primarily useful for debugging so is disabled by default.
	const write_cmd_log = F &redef;

	## This is an internally used function.
	const set_current_file: function(smb: Info, file_id: count) &redef;

	## This is an internally used function.
	const write_file_log: function(f: FileInfo) &redef;
}

redef record connection += {
	smb_pending_cmds : table[count, count] of Info &default=table();
};

redef record FileInfo += {
	## ID referencing this file.
	fid            : count   &optional;

	## Maintain a reference to the file record.
	f              : fa_file &optional;
};

const ports = { 139/tcp, 445/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(CMD_LOG, [$columns=SMB::Info]);
	Log::create_stream(FILES_LOG, [$columns=SMB::FileInfo]);
	Log::create_stream(MAPPING_LOG, [$columns=SMB::TreeInfo]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SMB, ports);
	}

function set_current_file(smb: Info, file_id: count)
	{
	if ( file_id !in smb$fid_map )
		{
		smb$fid_map[file_id] = smb$current_cmd$referenced_file;
		smb$fid_map[file_id]$fid = file_id;
		}
	
	smb$current_file = smb$fid_map[file_id];
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
		if ( c?$smb && c$smb?$current_file)
			{
			write_file_log(c$smb$current_file);
			}
		return;
		}
	}