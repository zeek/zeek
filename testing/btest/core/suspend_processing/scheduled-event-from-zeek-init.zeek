# @TEST-DOC: What network_time() does an event observe that's scheduled from zeek_init()
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

event zeek_scheduled()
	{
	print network_time(), "zeek_scheduled";
	}

event zeek_init()
	{
	print network_time(), "zeek_init";
	event zeek_post();
	schedule 0.0sec { zeek_scheduled() };

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
