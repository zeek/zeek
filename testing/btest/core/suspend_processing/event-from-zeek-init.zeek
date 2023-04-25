# @TEST-DOC: Previously, the zeek_post() event would have access to the first packet's network_time, even if suspend_processing() was called in zeek_init(). This changed in Zeek 6.0 to return 0.0 as network_time_init() is now available.
# @TEST-EXEC: echo "first line" > raw_file
# @TEST-EXEC: zeek -b -C -r $TRACES/tunnels/vxlan.pcap %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

type OneLine: record {
	s: string;
};

event one_line(desc: Input::EventDescription, e: Input::Event, s: string) {
	print network_time(), "one_line", s;
	continue_processing();
}

event zeek_post()
	{
	print network_time(), "zeek_post";
	}

event zeek_init()
	{
	print network_time(), "zeek_init";
	event zeek_post();
	suspend_processing();

	Input::add_event([
		$name="raw-read",
		$source="./raw_file",
		$reader=Input::READER_RAW,
		$mode=Input::STREAM,
		$fields=OneLine,
		$ev=one_line,
		$want_record=F,
	]);
	}

event network_time_init()
	{
	print network_time(), "network_time_init";
	}

event raw_packet(p: raw_pkt_hdr)
	{
	print network_time(), "raw_packet", p$ip;
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
