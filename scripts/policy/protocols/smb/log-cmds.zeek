##! Load this script to generate an SMB command log, smb_cmd.log.
##! This is primarily useful for debugging.

@load base/protocols/smb

module SMB;

export {
	redef enum Log::ID += {
		CMD_LOG,
	};

	global log_policy: Log::PolicyHook;

	## The server response statuses which are *not* logged.
	option ignored_command_statuses: set[string] = {
		"MORE_PROCESSING_REQUIRED",
	};
}

## Internal use only.
## Some commands shouldn't be logged by the smb1_message event.
const deferred_logging_cmds: set[string] = {
	"NEGOTIATE",
	"READ_ANDX",
	"SESSION_SETUP_ANDX",
	"TREE_CONNECT_ANDX",
};

event zeek_init() &priority=5
	{
	Log::create_stream(SMB::CMD_LOG, [$columns=SMB::CmdInfo, $path="smb_cmd", $policy=log_policy]);
	}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;

	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}

event smb1_error(c: connection, hdr: SMB1::Header, is_orig: bool)
	{
	if ( is_orig )
		return;

	# This is for deferred commands only.
	# The more specific messages won't fire for errors

	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command !in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;

	# If the command that is being looked at right now was
	# marked as PENDING, then we'll skip all of this and wait
	# for a reply that isn't marked pending.
	if ( c$smb_state$current_cmd$status == "PENDING" )
		return;

	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}
