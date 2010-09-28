# $Id: trim-trace-file.bro 6811 2009-07-06 20:41:10Z robin $
#
# Deletes the -w tracefile at regular intervals and starts from scratch. Separate 
# from rotate-logs.bro because we might want to have a shorter rotation interval 
# for this one due to its size.
#
# FIXME: Still, we eventually want to merge this with rotate-logs.bro by
# allowing per-file intervals for aux files. 

module TrimTraceFile;

export {
	const trim_interval = 10 mins &redef;
	}

global first_trim = T;

event trim_tracefile()
	{
	if ( bro_is_terminating() || trace_output_file == "" )
		return;

	if ( ! first_trim )
		{
		local info = rotate_file_by_name(trace_output_file);
		if ( info$old_name != "" )
			system(fmt("/bin/rm %s", info$new_name));
		}

	first_trim = F;
	schedule trim_interval { trim_tracefile() };
	}

event bro_init()
	{
	if ( trim_interval != 0 secs )
		schedule trim_interval { trim_tracefile() };
	}

