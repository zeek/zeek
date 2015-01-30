##! This script defines a postprocessing function that can be applied
##! to a logging filter in order to automatically SFTP
##! a log stream (or a subset of it) to a remote host at configurable
##! rotation time intervals.  Generally, to use this functionality
##! you must handle the :bro:id:`bro_init` event and do the following
##! in your handler:
##!
##! 1) Create a new :bro:type:`Log::Filter` record that defines a name/path,
##!    rotation interval, and set the ``postprocessor`` to
##!    :bro:id:`Log::sftp_postprocessor`.
##! 2) Add the filter to a logging stream using :bro:id:`Log::add_filter`.
##! 3) Add a table entry to :bro:id:`Log::sftp_destinations` for the filter's
##!    writer/path pair which defines a set of :bro:type:`Log::SFTPDestination`
##!    records.

module Log;

export {
	## Securely transfers the rotated log to all the remote hosts
	## defined in :bro:id:`Log::sftp_destinations` and then deletes
	## the local copy of the rotated log.  It's not active when
	## reading from trace files.
	##
	## info: A record holding meta-information about the log file to be
	##       postprocessed.
	##
	## Returns: True if sftp system command was initiated or
	##          if no destination was configured for the log as described
	##          by *info*.
	global sftp_postprocessor: function(info: Log::RotationInfo): bool;

	## A container that describes the remote destination for the SFTP command,
	## comprised of the username, host, and path at which to upload the file.
	type SFTPDestination: record {
		## The remote user to log in as.  A trust mechanism should be
		## pre-established.
		user: string;
		## The remote host to which to transfer logs.
		host: string;
		## The path/directory on the remote host to send logs.
		path: string;
	};

	## A table indexed by a particular log writer and filter path, that yields
	## a set of remote destinations.  The :bro:id:`Log::sftp_postprocessor`
	## function queries this table upon log rotation and performs a secure
	## transfer of the rotated log to each destination in the set.  This
	## table can be modified at run-time.
	global sftp_destinations: table[Writer, string] of set[SFTPDestination];

	## Default naming format for timestamps embedded into log filenames
	## that use the SFTP rotator.
	const sftp_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;
}

function sftp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( reading_traces() || [info$writer, info$path] !in sftp_destinations )
		return T;

	local command = "";
	for ( d in sftp_destinations[info$writer, info$path] )
		{
		local dst = fmt("%s/%s.%s.log", d$path, info$path,
		                strftime(Log::sftp_rotation_date_format, info$open));
		command += fmt("echo put %s %s | sftp -b - %s@%s;", info$fname, dst,
		               d$user, d$host);
		}

	command += fmt("/bin/rm %s", info$fname);
	system(command);
	return T;
	}
