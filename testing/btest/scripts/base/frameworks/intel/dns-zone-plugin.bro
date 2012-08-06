# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	Intel::insert([$str="bad.com", $subtype=Intel::DNS_ZONE, $meta=[$source="src1", $class=Intel::MALICIOUS]]);
	local query: Intel::Query = [$str="some.host.bad.com", $subtype=Intel::DOMAIN, $class=Intel::MALICIOUS];
	if ( Intel::matcher(query) )
		{
		print "It matched!";
		local items = Intel::lookup(query);
		for ( item in items )
			{
			print item$str;
			print item$subtype;
			}
		}
	}
