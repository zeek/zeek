# $Id: broctl-check.bro 6811 2009-07-06 20:41:10Z robin $
#
# Only loaded when checking configuration, not when running live.

@load rotate-logs

redef RotateLogs::rotate_on_shutdown=F;

	
		
