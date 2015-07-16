@load base/protocols/conn
@load ./tcp_functions

redef use_tcp_analyzer=T;

module TCPRETRANSMISSIONS;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:			time 	&log;
		uid:		string	&log;
		id:			conn_id	&log;

		label:		string  &log;
		seq:		count		&log;
		rtt:		double	&log;
		state:          int     &log;
                #state:		string	&log;
		orig:		bool	&log;		
		reason:         int     &log;
                #reason:		string	&log;
		rtype:          int     &log;
                #rtype:		string	&log;
		confidence:	double	&log &optional;
		
		nnseq:		count	&log;
		flags:		int		&log &optional;
	};

	global log_tcp_retransmissions: event(rec: Info);
}



event bro_init() &priority=5
	{	
		Log::create_stream(TCPRETRANSMISSIONS::LOG, [$columns=Info]);
	}
	
event conn_rexmit(	c: connection, 
					timestamp: time, 
					seq:count,
					is_orig: bool, 
					rtt:double, 
					state: int, 
					o_seq:count,
					beg_seq:count, 
					end_seq:count, 
					reason:int, 
					rtype:int, 
					confidence:double,
					flags:int) &priority=-5
	{			
		local rec: TCPRETRANSMISSIONS::Info = [	
			$ts = timestamp, 
			$uid = c$uid, 	
			$id = c$id,
			$label = "TCP::Retransmissions",
			$seq = seq,
			$rtt = rtt,
			$state = state,
			$orig = is_orig,
            $reason = reason,
            #$confidence = confidence,
			$rtype = rtype,
			$nnseq = o_seq,
			$flags = flags];
		Log::write(TCPRETRANSMISSIONS::LOG, rec);
	}

event conn_spurious_dsack(c: connection,
            timestamp: time,
            seq:count,
            is_orig: bool,
            rtt:double,
            state: int,
            o_seq:count,
            beg_seq:count,
            end_seq:count,
            reason:int,
            rtype:int)
    {
            local rec: TCPRETRANSMISSIONS::Info = [
			$ts = timestamp,
			$uid = c$uid,
			$id = c$id,
			$label = "TCP::SpuriousRetransmission",
			$seq = seq,
			$rtt = rtt,
			$state = state,
			$orig = is_orig,
                        $reason = reason,
			$rtype = rtype,
			$nnseq = o_seq];
            Log::write(TCPRETRANSMISSIONS::LOG, rec);
    }
