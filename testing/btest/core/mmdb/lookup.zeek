# @TEST-DOC: Test basic DB lookups for success/failure.
#
# @TEST-REQUIRES: $BUILD/zeek-config --have-geoip
#
# @TEST-EXEC: zeek -b %INPUT >out.nodb
# @TEST-EXEC: btest-diff out.nodb
# @TEST-EXEC: cp -R $FILES/mmdb ./mmdb
# @TEST-EXEC: zeek -b %INPUT >out.db
# @TEST-EXEC: btest-diff out.db

redef mmdb_dir = "./mmdb";

function do_lookups(a: addr)
	{
	print a, "location", lookup_location(a);
	print a, "asn", lookup_autonomous_system(a);
	}

event zeek_init()
	{
	# Succeeding calls:
	do_lookups(128.3.0.1);
	do_lookups([2607:f140::1]);

	# Failing ones:
	do_lookups(10.0.0.1);
	do_lookups([fc00::1]);
	}
