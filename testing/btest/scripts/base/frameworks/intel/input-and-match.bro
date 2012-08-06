# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE intel.dat
#fields	ip	net	str	subtype	meta.source	meta.class	meta.desc	meta.url	meta.tags
1.2.3.4	-	-	-	source1	Intel::MALICIOUS	this host is just plain baaad	http://some-data-distributor.com/1234	foo,bar
1.2.3.4	-	-	-	source1	Intel::MALICIOUS	this host is just plain baaad	http://some-data-distributor.com/1234	foo,bar
-	-	e@mail.com	Intel::EMAIL	source1	Intel::MALICIOUS	Phishing email source	http://some-data-distributor.com/100000	-
@TEST-END-FILE

@load frameworks/communication/listen

redef Intel::read_files += { "intel.dat" };

event do_it(allowed_loops: count)
	{
	if ( Intel::matcher([$str="e@mail.com", $subtype=Intel::EMAIL, $class=Intel::MALICIOUS]) &&
	     Intel::matcher([$ip=1.2.3.4, $class=Intel::MALICIOUS]) )
		{
		# Once the match happens a single time we print and shutdown.
		print "Matched it!";
		terminate_communication();
		return;
		}
	
	if ( allowed_loops > 0 )
		schedule 100msecs { do_it(allowed_loops-1) };
	else
		terminate_communication();
	}


event bro_init()
	{
	event do_it(20);
	}
