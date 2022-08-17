# @TEST-EXEC: zeek -b -r $TRACES/tcp/options.pcap %INPUT > out
# @TEST-EXEC: zeek -b -r $TRACES/tcp/option-sack.pcap %INPUT > out-sack
# @TEST-EXEC: zeek -b -r $TRACES/tcp/option-27.pcap %INPUT > out-27
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out-sack
# @TEST-EXEC: btest-diff out-27

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count)
	{
	print c$id, is_orig, opt, optlen;
	}

event tcp_options(c: connection, is_orig: bool, options: TCP::OptionList)
	{
	print c$id, is_orig;

	for ( i in options )
		{
		local o = options[i];
		print fmt("  kind: %s, length: %s", o$kind, o$length);

		if ( o?$data )
			print fmt("    data (%s): %s", |o$data|, o$data);
		else
			{
			switch ( o$kind ) {
			case 2:
				print fmt("    mss: %s", o$mss);
				break;
			case 3:
				print fmt("    window scale: %s", o$window_scale);
				break;
			case 4:
				print fmt("    sack permitted");
				break;
			case 5:
				print fmt("    sack: %s", o$sack);
				break;
			case 8:
				print fmt("    send ts: %s", o$send_timestamp);
				print fmt("    echo ts: %s", o$echo_timestamp);
				break;
			case 27:
				print fmt("     TTL Diff: %s", o$ttl_diff);
				break;
			}
			}
		}
	}
