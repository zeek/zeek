# @TEST-DOC: verifies that the explicit BiFs for loading MMDBs work, including when re-opening.
#
# Like other MMDB tests, this uses a pcap to use each packet as a driver to
# touch the DBs involved upon each packet, triggering DB reloads.
#
# @TEST-REQUIRES: $BUILD/zeek-config --have-geoip
#
# @TEST-EXEC: cp -R $FILES/mmdb ./mmdb
# @TEST-EXEC: zeek -b -r $TRACES/rotation.trace %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff-cut -m reporter.log

@load base/frameworks/reporter

global pkt = 0;
global asn_fn = "./mmdb/GeoLite2-ASN.mmdb";
global city_fn = "./mmdb/GeoLite2-City.mmdb";

function timestamp(n: count): string
	{
	assert n <= 60;
	return fmt("2020-01-01T00:%s:00", n);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	++pkt;

	print network_time(), pkt, 128.3.0.1, "asn", lookup_autonomous_system(128.3.0.1);
	print network_time(), pkt, 128.3.0.1, "location", lookup_location(128.3.0.1);
	print network_time(), pkt, 131.243.0.1, "asn", lookup_autonomous_system(131.243.0.1);
	print network_time(), pkt, 131.243.0.1, "location", lookup_location(131.243.0.1);

	# Increment MMDBs' modification time, triggering a re-open.
	if ( ! piped_exec(fmt("touch -d %s %s", timestamp(pkt), safe_shell_quote(asn_fn)), "") )
		exit(1);

	if ( ! piped_exec(fmt("touch -d %s %s", timestamp(pkt), safe_shell_quote(city_fn)), "") )
		exit(1);

	if ( pkt == 4 )
		terminate();
	}

event zeek_init()
	{
	if ( ! mmdb_open_asn_db(asn_fn) )
		Reporter::fatal("failed to open asn_db " + asn_fn);

	if ( ! mmdb_open_location_db(city_fn) )
		Reporter::fatal("failed to open location db " + city_fn);
	}
