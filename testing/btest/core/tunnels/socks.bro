# @TEST-EXEC: bro -Cr $TRACES/tunnels/socks.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

event socks_request(c: connection, request_type: count, dstaddr: addr,
		    dstname: string, p: port, user: string)
	{
	print c;
	print "---";
	print request_type;
	print dstaddr;
	print dstname;
	print p;
	print user;
	}


