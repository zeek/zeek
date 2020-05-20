# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	print "http_all_headers";
	print hlist;
	}

event mime_all_headers(c: connection, hlist: mime_header_list)
	{
	print "mime_all_headers";
	print hlist;
	}
