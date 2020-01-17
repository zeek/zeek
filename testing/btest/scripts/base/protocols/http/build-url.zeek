# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT >output
# @TEST-EXEC: btest-diff output

function test(rec: HTTP::Info, expect: string)
	{
	local result = HTTP::build_url(rec);
	print fmt("Have: %s Expected: %s -> %s", result, expect, (result == expect ? "SUCCESS" : "FAIL"));
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
	{
        test(c$http, "192.150.187.43/download/CHANGES.bro-aux.txt");
	
	# We fake some request instances for testing.
        c$http$id$resp_p = 123/tcp;
        test(c$http, "192.150.187.43:123/download/CHANGES.bro-aux.txt");

        c$http$uri = "/";
        test(c$http, "192.150.187.43:123/");
	
	c$http$uri = "http://proxied.host/some/document";
        test(c$http, "http://proxied.host/some/document");
	}
