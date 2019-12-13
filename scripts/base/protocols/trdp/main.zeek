
module TRDP;

const ports = { 20550/tcp, 20550/udp };
redef likely_server_ports += { ports };

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:            time               &log;
		uid:           string             &log;
		id:            conn_id            &log;
		sequence_counter: count           &log &default=0;
		protocol_version: string &log;
		msg_type: string  &log &optional;
		com_id: string  &log &optional;
		etb_top_cnt: count &log &optional;
		op_trn_topo_cnt: count &log &optional;
		dataset_length: count &log &optional;
		reserved01: count &log &default=0;
		reply_com_id: string &log &optional;
		reply_ip_address: string &log &optional;
		header_fcs: count &log &optional;
		dataset: count &log &optional;
	};

}

redef record connection += {
	trdp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(TRDP::LOG, [$columns=Info, $path="trdp"]);
	}
