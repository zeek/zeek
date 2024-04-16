# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: cp zeekproc/.stdout output
# @TEST-EXEC: zeek-cut -m seen.indicator seen.indicator_type seen.where seen.node < zeekproc/intel.log > intel.log
# @TEST-EXEC: btest-diff intel.log
# @TEST-EXEC: btest-diff output

@load base/frameworks/intel

redef exit_only_after_terminate = T;

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print "Intel::match", s$indicator, s$indicator_type;
	}

hook Intel::seen_policy(s: Intel::Seen, found: bool)
	{
	print "Intel::seen_policy", s$indicator, s$indicator_type, "found", found;

	# No event generation for zeek.org
	if ( s$indicator == "zeek.org" )
		break;
	}

event seen_policy_test()
	{
	Intel::seen([$indicator="example.com", $indicator_type=Intel::DOMAIN, $where=Intel::IN_ANYWHERE]);
	Intel::seen([$indicator="zeek.org", $indicator_type=Intel::DOMAIN, $where=Intel::IN_ANYWHERE]);
	Intel::seen([$indicator="domain.de", $indicator_type=Intel::DOMAIN, $where=Intel::IN_ANYWHERE]);
	Intel::seen([$indicator="nobody", $indicator_type=Intel::USER_NAME, $where=Intel::IN_ANYWHERE]);
	Intel::seen([$indicator="root", $indicator_type=Intel::USER_NAME, $where=Intel::IN_ANYWHERE]);

	terminate();
	}

event zeek_init()
	{
	local meta = Intel::MetaData($source="btest");
	local i0 = Intel::Item($indicator="example.com", $indicator_type=Intel::DOMAIN, $meta=meta);
	local i1 = Intel::Item($indicator="zeek.org", $indicator_type=Intel::DOMAIN, $meta=meta);
	local i2 = Intel::Item($indicator="root", $indicator_type=Intel::USER_NAME, $meta=meta);
	for ( _, i in vector(i0, i1, i2) )
		Intel::insert(i);


	event seen_policy_test();
	}
