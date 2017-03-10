module ICMP_Echo;

export {
	redef enum Log::ID += { LOG };

    type Info: record {
    	ts:           time   &log;
    	cuid:         string &log;
    	tx_host:      addr   &log;
    	rx_host:      addr   &log;
        echo_type:    string &log;
        echo_id:      count  &log;
        echo_seq:     count  &log;
        echo_payload: string &log;
    };
}

redef record connection += {
	icmp: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(ICMP_Echo::LOG, [$columns=Info, $path="icmp_echo"]);
	}

event icmp_echo_request(c: connection,
	                    icmp: icmp_conn,
	                    id: count,
	                    seq: count,
	                    payload: string)

	{
	local rec: ICMP_Echo::Info = [$ts=network_time(),
	                              $cuid=c$uid,
	                              $tx_host=c$id$orig_h,
	                              $rx_host=c$id$resp_h,
	                              $echo_type="request",
	                              $echo_id=id,
	                              $echo_seq=seq,
	                              $echo_payload=payload];
	Log::write(ICMP_Echo::LOG, rec);
	}

event icmp_echo_reply(c: connection,
	                  icmp: icmp_conn,
	                  id: count,
	                  seq: count,
	                  payload: string)

	{
	local rec: ICMP_Echo::Info = [$ts=network_time(),
	                              $cuid=c$uid,
	                              $tx_host=c$id$resp_h, # Reply is the
	                              $rx_host=c$id$orig_h, # opposite of flow
	                              $echo_type="reply",
	                              $echo_id=id,
	                              $echo_seq=seq,
	                              $echo_payload=payload];
	Log::write(ICMP_Echo::LOG, rec);
	}