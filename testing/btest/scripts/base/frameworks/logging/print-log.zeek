#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff print_statements.log
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff otherfile

redef Log::print_to_log = Log::REDIRECT_ALL;
redef Log::print_log_path = "print_statements";

event zeek_init()
	{
	local f = open("otherfile");
	print f, "hello world ,";
	print "hello world ,";
	print f,2,T;
	print 2,T;
	close(f);
	}