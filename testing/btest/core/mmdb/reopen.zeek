# @TEST-DOC: Change the modification time of the mmdb database on every packet. This triggers reopening of the MMDB database.
#
# @TEST-REQUIRES: grep -q "#define USE_GEOIP" $BUILD/zeek-config.h
#
# @TEST-EXEC: cp -R $FILES/mmdb ./mmdb
# @TEST-EXEC: zeek -b -r $TRACES/rotation.trace %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: zeek-cut -m < reporter.log > reporter.log.tmp && mv reporter.log.tmp reporter.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff reporter.log

@load base/frameworks/reporter

redef mmdb_dir = "./mmdb";

global pkt = 0;

function timestamp(n: count): string
	{
	return fmt("2020-01-01T00:%s:00", n);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	++pkt;

	# Increment MMDB's modification time.
	local asn_fn = safe_shell_quote(mmdb_dir + "/GeoLite2-ASN.mmdb");
	local city_fn = safe_shell_quote(mmdb_dir + "/GeoLite2-City.mmdb");

	if ( ! piped_exec(fmt("touch -d %s %s", timestamp(pkt), asn_fn), "") )
		exit(1);

	if ( ! piped_exec(fmt("touch -d %s %s", timestamp(pkt), city_fn), "") )
		exit(1);

	print network_time(), pkt, 128.3.0.1, "asn", lookup_autonomous_system(128.3.0.1);
	print network_time(), pkt, 128.3.0.1, "location", lookup_location(128.3.0.1);
	print network_time(), pkt, 131.243.0.1, "asn", lookup_autonomous_system(131.243.0.1);
	print network_time(), pkt, 131.243.0.1, "location", lookup_location(131.243.0.1);

	if ( pkt == 4 )
		terminate();
	}
