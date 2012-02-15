##! This file is meant to print messages on stdout for settings that would be
##! good to set in most cases or other things that could be done to achieve 
##! better detection.

@load base/utils/site

event bro_init() &priority=-10
	{
	if ( |Site::local_nets| == 0 )
		print "WARNING: No Site::local_nets have been defined.  It's usually a good idea to define your local networks.";
	}
