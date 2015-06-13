@load base/protocols/conn
@load ./tcp_functions

redef use_tcp_analyzer=T;

module TCPRECOVERY;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:		time 	&log;
		uid:		string	&log;
		id:		conn_id	&log;

		label:		string  &log;
		seq:		count	&log;
		rtt:		double	&log;
		state:          int     &log;
		orig:		bool	&log;
		nnseq:		count	&log;
	};

	global log_tcp_recovery: event(rec: Info);
}

event bro_init() &priority=5
	{	
		Log::create_stream(TCPRECOVERY::LOG, [$columns=Info]);
	}

event conn_limited_transmit(c: connection, 
        timestamp: time,
        seq:count,
        is_orig: bool,
        rtt:double,
        state: int,
        o_seq:count,
        beg_seq:count,
        end_seq:count)
    {
                local rec: TCPRECOVERY::Info = [
			$ts = timestamp,
			$uid = c$uid,
			$id = c$id,
			$label = "TCP::LIMITEDTRANSMIT",
			$seq = seq,
			$rtt = rtt,
			$state = state,
			$orig = is_orig,
			$nnseq = o_seq];
		Log::write(TCPRECOVERY::LOG, rec);
    }

event conn_fast_recovery(c: connection, timestamp: time, seq:count, is_orig: bool, rtt:double, state: int, o_seq:count, beg_seq:count, end_seq:count)
    {
                local rec: TCPRECOVERY::Info = [
			$ts = timestamp,
			$uid = c$uid,
			$id = c$id,
			$label = "TCP::FASTRECOVERY",
			$seq = seq,
			$rtt = rtt,
			$state = state,
			$orig = is_orig,
			$nnseq = o_seq];
		Log::write(TCPRECOVERY::LOG, rec);
    }
