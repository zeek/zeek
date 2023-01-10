# @TEST-EXEC: zeek -b -r $TRACES/http/http-filename.pcap %INPUT
# @TEST-EXEC: btest-diff intel.log

@load base/frameworks/intel
@load frameworks/intel/seen
@load base/protocols/http

redef Intel::read_files = { "./intel.dat" };

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
test.json	Intel::FILE_NAME	source1	A JSON file	https://www.json.org/json-en.html
@TEST-END-FILE

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( /intel.dat/ in source )
		continue_processing();
	}
