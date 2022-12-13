# Skip this test for OpenSSL 3.0 at the moment. We will switch it to only OpenSSL 3.0, once
# a majority of distributions use is.
# @TEST-REQUIRES: ! grep -q "^ZEEK_HAVE_OPENSSL_3_0.*true" $BUILD/CMakeCache.txt

# @TEST-EXEC: zeek -r $TRACES/smtp.trace policy/misc/dump-events %INPUT >all-events.log
# @TEST-EXEC: zeek -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include_args=F >all-events-no-args.log
# @TEST-EXEC: zeek -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include=/smtp_/ >smtp-events.log
# @TEST-EXEC: zeek -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::dump_all_events=T | grep -v "CPU: interval\|samples: load_sample_info\|path: string" > really-all-events.log
#
# @TEST-EXEC: btest-diff all-events.log
# @TEST-EXEC: btest-diff all-events-no-args.log
# @TEST-EXEC: btest-diff smtp-events.log
# @TEST-EXEC: btest-diff really-all-events.log

# There is some kind of race condition between the MD5 and SHA1 events, which are added
# by the SSL parser. Just remove MD5, this is not important for this test.

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=-5
	{
	if ( ! c?$ssl )
		return;

	Files::remove_analyzer(f, Files::ANALYZER_MD5);
	}
