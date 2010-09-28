# $Id: remote-print.bro 415 2004-09-17 03:25:12Z vern $
#
# Write remote print messages into local files.

event print_hook(f: file, s: string)
	{
	if ( is_remote_event() )
		print f, s;
	}
