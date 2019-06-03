# @TEST-EXEC: zeek -Cr $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff intel.log

#@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
upload.wikimedia.org	Intel::DOMAIN	source1	somehow bad	http://some-data-distributor.com/1
meta.wikimedia.org	Intel::DOMAIN	source1	also bad	http://some-data-distributor.com/1
#@TEST-END-FILE

#@TEST-START-FILE whitelist.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.whitelist	meta.url
meta.wikimedia.org	Intel::DOMAIN	source2	also bad	T	http://some-data-distributor.com/1
#@TEST-END-FILE

@load base/frameworks/intel
@load frameworks/intel/whitelist
@load frameworks/intel/seen

redef Intel::read_files += {
	"intel.dat",
	"whitelist.dat",
};

global total_files_read = 0;

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	# Wait until both intel files are read.
	if ( /^intel-/ in name && (++total_files_read == 2) )
		{
		continue_processing();
		}
	}

