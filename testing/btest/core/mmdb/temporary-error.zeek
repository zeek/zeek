# @TEST-DOC: Test a few error and recovery cases (corrupted, removed and restored MMDB databases).
#
# @TEST-REQUIRES: grep -q "#define USE_GEOIP" $BUILD/zeek-config.h
#
# @TEST-EXEC: cp -R $FILES/mmdb ./mmdb
# @TEST-EXEC: cp -R $FILES/mmdb ./mmdb-backup
# @TEST-EXEC: zeek -b -r $TRACES/rotation.trace %INPUT mmdb_dir=./mmdb >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: zeek-cut -m < reporter.log > reporter.log.tmp && mv reporter.log.tmp reporter.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff reporter.log

@load base/frameworks/reporter

redef mmdb_dir = "./mmdb";

global pkt = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	++pkt;

	local asn_fn = safe_shell_quote(mmdb_dir + "/GeoLite2-ASN.mmdb");
	local city_fn = safe_shell_quote(mmdb_dir + "/GeoLite2-City.mmdb");

	local asn_fn_backup = safe_shell_quote(mmdb_dir + "-backup/GeoLite2-ASN.mmdb");
	local city_fn_backup = safe_shell_quote(mmdb_dir + "-backup/GeoLite2-City.mmdb");

	if ( pkt == 1 )
		{
		print "start";
		}
	if ( pkt == 2 )
		{
		print "corrupting db";
		if ( ! piped_exec(fmt("truncate --size=8 %s", asn_fn), "") )
			exit(1);

		if ( ! piped_exec(fmt("truncate --size=8 %s", city_fn), "") )
			exit(1);
		}
	else if ( pkt == 4 )
		{
		print "unlinking";
		if ( ! piped_exec(fmt("rm %s", asn_fn), "") )
			exit(1);

		if ( ! piped_exec(fmt("rm %s", city_fn), "") )
			exit(1);
		}
	else if ( pkt == 6 )
		{
		# This should provoke an inode change.
		print "unlinking and restoring";
		if ( ! piped_exec(fmt("mv %s %s.tmp; cp %s.tmp %s", asn_fn, asn_fn, asn_fn, asn_fn), "") )
			exit(1);

		if ( ! piped_exec(fmt("mv %s %s.tmp; cp %s.tmp %s", city_fn, city_fn, city_fn, city_fn), "") )
			exit(1);
		}
	else if ( pkt == 7 )
		{
		print "done";
		terminate();
		return;
		}
	else if ( pkt == 3 || pkt == 5 )
		{
		print "restoring backup db";
		if ( ! piped_exec(fmt("cp %s %s", asn_fn_backup, asn_fn), "") )
			exit(1);

		if ( ! piped_exec(fmt("cp %s %s", city_fn_backup, city_fn), "") )
			exit(1);
		}

	# Set MMDB's modification time to current network time for predictability.
	if ( ! piped_exec(fmt("test -f %s && touch -d @%s %s", asn_fn, network_time(), asn_fn), "") )
		exit(1);

	if ( ! piped_exec(fmt("test -f %s && touch -d @%s %s", city_fn, network_time(), city_fn), "") )
		exit(1);

	print network_time(), pkt, 128.3.0.1, "asn", lookup_autonomous_system(128.3.0.1);
	print network_time(), pkt, 128.3.0.1, "location", lookup_location(128.3.0.1);
	}
