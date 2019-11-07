#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff print_statements.log

redef Log::print_to_log = T;
redef Log::print_log_path = "print_statements";

event zeek_init()
	{
	print "hello world ,";
	print 2,T;
	}
