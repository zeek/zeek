# $Id: log-append.bro 2797 2006-04-23 05:56:24Z vern $

# By default, logs are overwritten when opened, deleting the contents
# of any existing log of the same name.  Loading this module changes the
# behavior to appending.

function open_log_file(tag: string): file
	{
	return open_for_append(log_file_name(tag));
	}
