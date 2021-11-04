##! Deletes the ``-w`` tracefile at regular intervals and starts a new file
##! from scratch.

module TrimTraceFile;

export {
	## The interval between times that the output tracefile is rotated.
	const trim_interval = 10 mins &redef;

	## This event can be generated externally to this script if on-demand
	## tracefile rotation is required with the caveat that the script
	## doesn't currently attempt to get back on schedule automatically and
	## the next trim likely won't happen on the
	## :zeek:id:`TrimTraceFile::trim_interval`.
	global go: event(first_trim: bool);
	}

event TrimTraceFile::go(first_trim: bool)
	{
	if ( zeek_is_terminating() || trace_output_file == "" )
		return;

	if ( ! first_trim )
		{
		local info = rotate_file_by_name(trace_output_file);
		if ( info$old_name != "" )
			system(fmt("/bin/rm %s", safe_shell_quote(info$new_name)));
		}

	schedule trim_interval { TrimTraceFile::go(F) };
	}

event zeek_init()
	{
	if ( trim_interval > 0 secs )
		schedule trim_interval { TrimTraceFile::go(T) };
	}
