#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "123/tcp" as port;
	print "123/udp" as port;
	print "123/icmp" as port;
	print "0/tcp" as port;
	print "0/udp" as port;
	print "0/icmp" as port;
	print "not a port" ?as port;
	print "" ?as port;
	print "123" ?as port;
	print "123/" ?as port;
	}
