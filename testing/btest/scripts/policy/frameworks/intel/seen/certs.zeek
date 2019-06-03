# @TEST-EXEC: zeek -Cr $TRACES/tls/ecdsa-cert.pcap %INPUT
# @TEST-EXEC: cat intel.log > intel-all.log
# @TEST-EXEC: zeek -r $TRACES/tls/ssl.v3.trace %INPUT
# @TEST-EXEC: cat intel.log >> intel-all.log
# @TEST-EXEC: btest-diff intel-all.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
www.pantz.org	Intel::DOMAIN	source1	test entry	http://some-data-distributor.com/100000
www.dresdner-privat.de	Intel::DOMAIN	source1	test entry	http://some-data-distributor.com/100000
2c322ae2b7fe91391345e070b63668978bb1c9da	Intel::CERT_HASH	source1	test entry	http://some-data-distributor.com/100000
@TEST-END-FILE

@load base/frameworks/intel
@load base/protocols/ssl
@load frameworks/intel/seen

redef Intel::read_files += { "intel.dat" };

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	continue_processing();
	}

