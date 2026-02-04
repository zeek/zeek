# Define priority with '&priority' before the opening brace
event zeek_init() &priority=-5
	{
	print "This handler uses state created by other events - it should go late!";
	}

# Higher priority runs first
event zeek_init() &priority=300
	{
	print "This handler creates state - it should go early!";
	}
