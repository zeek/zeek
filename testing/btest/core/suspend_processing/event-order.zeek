# @TEST-DOC: Previously, suspend_processing() within zeek_init() would not prevent packets and connection processing, it does with Zeek 6.0 and later.
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

event zeek_init()
	{
	print network_time(), "zeek_init";
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

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done", path;
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
