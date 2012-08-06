#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	Intel::insert([$ip=1.2.3.4, $meta=[$source="zeus-tracker", $class=Intel::MALICIOUS, $tags=set("example-tag1", "example-tag2")]]);
	Intel::insert([$str="http://www.google.com/", $subtype=Intel::URL, $meta=[$source="source2", $class=Intel::MALICIOUS, $tags=set("infrastructure", "google")]]);
	}

event bro_done()
	{
	local orig_h = 1.2.3.4;
	
	if ( Intel::matcher([$ip=orig_h, $and_tags=set("example-tag1", "example-tag2")]) )
		print "VALID";
	
	if ( Intel::matcher([$ip=orig_h, $and_tags=set("don't match")]) )
		print "INVALID";
	
	if ( Intel::matcher([$ip=orig_h, $pred=function(meta: Intel::Item): bool { return T; } ]) )
		print "VALID";
		
	if ( Intel::matcher([$ip=4.3.2.1, $pred=function(meta: Intel::Item): bool { return T; } ]) )
		print "INVALID";

	if ( Intel::matcher([$ip=orig_h, $pred=function(meta: Intel::Item): bool { return F; } ]) )
		print "INVALID";
		
	if ( Intel::matcher([$str="http://www.google.com/", $subtype=Intel::URL, $and_tags=set("google")]) )
		print "VALID";
		
	if ( Intel::matcher([$str="http://www.google.com/", $subtype=Intel::URL, $and_tags=set("woah")]) )
		print "INVALID";

	if ( Intel::matcher([$str="http://www.example.com", $subtype=Intel::URL]) )
		print "INVALID";
	}
