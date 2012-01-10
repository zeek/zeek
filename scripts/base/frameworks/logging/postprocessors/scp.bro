##! This script defines a postprocessing function that can be applied
##! to a logging filter in order to automatically SCP (secure copy)
##! a log stream (or a subset of it) to a remote host at configurable
##! rotation time intervals.

module Log;

export {
	## This postprocessor SCP's the rotated-log to all the remote hosts
	## defined in :bro:id:`Log::scp_destinations` and then deletes
	## the local copy of the rotated-log.  It's not active when
	## reading from trace files.
	global scp_postprocessor: function(info: Log::RotationInfo): bool;

	## A container that describes the remote destination for the SCP command
	## argument as ``user@host:path``.
	type SCPDestination: record {
		user: string;
		host: string;
		path: string;
	};

	## A table indexed by a particular log writer and filter path, that yields
	## a set remote destinations.  The :bro:id:`Log::scp_postprocessor`
	## function queries this table upon log rotation and performs a secure
	## copy of the rotated-log to each destination in the set.
	global scp_destinations: table[Writer, string] of set[SCPDestination];

	## Default naming format for timestamps embedded into log filenames
	## that use the SCP rotator.
	const scp_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;
}

function scp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( reading_traces() || [info$writer, info$path] !in scp_destinations )
		return T;

	local command = "";
	for ( d in scp_destinations[info$writer, info$path] )
		{
		local dst = fmt("%s/%s.%s.log", d$path, info$path,
                        strftime(Log::scp_rotation_date_format, info$open));
		command += fmt("scp %s %s@%s:%s;", info$fname, d$user, d$host, dst);
		}

	command += fmt("/bin/rm %s", info$fname);
	system(command);
	return T;
	}
