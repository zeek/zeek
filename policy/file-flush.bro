# $Id: file-flush.bro 786 2004-11-24 08:25:16Z vern $

# Causes all files to be flushed every file_flush_interval seconds.
# Useful if you want to poke through the log files in real time,
# particularly if network traffic is light.

global file_flush_interval = 10 sec &redef;

event file_flush_event()
	{
	flush_all();
	schedule file_flush_interval { file_flush_event() };
	}

event bro_init()
	{
	schedule file_flush_interval { file_flush_event() };
	}
