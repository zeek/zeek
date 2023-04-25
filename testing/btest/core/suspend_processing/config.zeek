# @TEST-DOC: Test that finishing reading an intel file resumes processing and network_time() isn't initialized until continue_processing() happens.
# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

@load base/frameworks/intel


@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
putty.exe	Intel::FILE_NAME	source1	SSH utility	https://www.putty.org
zeek.exe	Intel::FILE_NAME	source1	A network monitor	https://zeek.org
@TEST-END-FILE

redef Intel::read_files += { "intel.dat" };

event Input::end_of_data(name: string, source: string)
	{
	print network_time(), "end_of_data", name, source;
	if ( /intel.dat/ in source )
		continue_processing();
	}

event zeek_init()
	{
	print network_time(), "zeek_init";
	suspend_processing();
	}

event network_time_init()
	{
	print network_time(), "network_time_init";
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done", path;
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
