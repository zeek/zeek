event zeek_init()
	{
	# Prints will probably happen in numerical order
	print "1. Requesting DNS...";

	# 'when' handles waiting for lookup_hostname_txt to finish.
	# The code inside curly braces executes when it is complete.
	when ( local result = lookup_hostname_txt("www.zeek.org") )
		{
		print fmt("3. Found DNS result: %s", result);
		}
	# You could optionally add a "timeout" here, too.

	# This code will execute immediately, it will not wait for the result
	# from lookup_hostname_txt
	print "2. Request sent, moving on";
	}
