# $Id: standalone.rotate-logs.bro 6811 2009-07-06 20:41:10Z robin $

redef log_rotate_interval = 24hrs;
redef log_rotate_base_time = "0:00";
redef RotateLogs::default_postprocessor = "archive-log";

event file_opened(f: file)
	{
	# Create a link from the archive directory to the newly created file.
	if ( ! bro_is_terminating() )
		system(fmt("create-link-for-log %s", get_file_name(f)));
	}

