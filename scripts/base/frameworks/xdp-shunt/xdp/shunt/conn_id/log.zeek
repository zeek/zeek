@load base/protocols/conn
@load xdp/shunt/conn_id

module XDP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		id: XDP::canonical_id &log;
		bytes_shunted: count &log;
		packets_shunted: count &log;
		last_packet: time &log &optional;
	};
}

redef record connection += {
	xdp_shunt: Info &optional;
};

function make_info(cid: XDP::canonical_id, stats: XDP::ShuntedStats): Info
	{
	local info: Info = [$id=cid,
	    $bytes_shunted=stats$bytes_from_1 + stats$bytes_from_2,
	    $packets_shunted=stats$packets_from_1 + stats$packets_from_2];
	if ( stats?$timestamp )
		info$last_packet = stats$timestamp;

	return info;
	}

event XDP::Shunt::ConnID::unshunted_conn(can_id: XDP::canonical_id, stats: XDP::ShuntedStats)
	{
	Log::write(LOG, make_info(can_id, stats));
	}

event zeek_init()
	{
	Log::create_stream(XDP::LOG, [$columns=Info, $path="xdp_shunt"]);
	}
