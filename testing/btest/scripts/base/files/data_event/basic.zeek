# Just a very basic test to check if ANALYZER_DATA_EVENT works.
# Also check if "in" works with binary data.
# @TEST-EXEC: zeek -r $TRACES/pe/pe.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

event stream_data(f: fa_file, data: string)
	{
	if ( "Windows" in data )
		{
		print "Found";
		}
	}

event file_new (f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,
		[$stream_event=stream_data]);
	}

