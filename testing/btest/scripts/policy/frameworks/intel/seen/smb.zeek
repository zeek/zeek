# @TEST-EXEC: zeek -C -r $TRACES/smb/smb2readwrite.pcap %INPUT
# @TEST-EXEC: btest-diff intel.log

@load base/frameworks/intel
@load frameworks/intel/seen

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
pythonfile	Intel::FILE_NAME	source1	test entry	http://some-data-distributor.com/100000
@TEST-END-FILE

redef Intel::read_files += { "intel.dat" };

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	continue_processing();
	}
