#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	Intel::insert([$ip=1.2.3.4, $tags=set("zeustracker.abuse.ch", "malicious")]);
	Intel::insert([$str="http://www.google.com/", $subtype="url", $tags=set("infrastructure", "google")]);
	Intel::insert([$str="Ab439G32F...", $subtype="x509_cert", $tags=set("bad")]);
	Intel::insert([$str="Ab439G32F...", $tags=set("bad")]);
	}

event bro_done()
	{
	local orig_h = 1.2.3.4;
	
	if ( Intel::matcher([$ip=orig_h, $and_tags=set("malicious")]) )
		print "VALID";
	
	if ( Intel::matcher([$ip=orig_h, $and_tags=set("don't match")]) )
		print "INVALID";
	
	if ( Intel::matcher([$ip=orig_h, $pred=function(meta: Intel::MetaData): bool { return T; } ]) )
		print "VALID";
		
	if ( Intel::matcher([$ip=orig_h, $pred=function(meta: Intel::MetaData): bool { return F; } ]) )
		print "INVALID";
		
	if ( Intel::matcher([$str="http://www.google.com/", $subtype="url", $tags=set("google")]) )
		print "VALID";
		
	if ( Intel::matcher([$str="http://www.example.com", $subtype="url"]) )
		print "INVALID";
	}
