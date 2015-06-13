@load base/protocols/conn

redef use_tcp_analyzer=T;

module TCPREORDERING;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:						time 	&log;
		uid:					string	&log;
		id:						conn_id	&log;

		label:					string  &log;
		seq:					count		&log;
		gap:					double 	&log;
		rtt:					double	&log &optional;
		segments_outoforder:	int		&log;
		orig:					bool	&log;
		ambiguous:				bool	&log &optional;		
		
		nnseq:					count	&log;
	};

	global log_tcp_reordering: event(rec: Info);
}

event bro_init() &priority=5
	{	
		Log::create_stream(TCPREORDERING::LOG, [$columns=Info]);
	}

#I want to call this a tcp_reordering_event later
event conn_ooo_event(	c: connection, 
                        timestamp:time,
                        is_orig:bool,
                        seq:count,
                        gap:double,
                        rtt:double,
                        num_seq:int,
                        o_seq:count,
                        beg_seq:count,
                        end_seq:count) &priority=-5
    {
        local rec: TCPREORDERING::Info = [
                $ts   				 = timestamp,
                $uid  				 = c$uid,
                $id   				 = c$id,
                $label				 = "TCP::Reordering",
                $seq  				 = seq,
                $gap  				 = gap,
                $rtt   				 = rtt,
                $segments_outoforder             = num_seq,
                $orig 				 = is_orig,
				$ambiguous			 = F,
                $nnseq 				 = o_seq ];
        Log::write(TCPREORDERING::LOG, rec);
    }

#I want to call this a tcp_reordering event as well. Classify it with a different tag.
event conn_ambi_order(c: connection,
                        timestamp:time,
                        is_orig:bool,
                        seq:count,
                        gap:double,
                        num_seq:int,
                        o_seq:count,
                        beg_seq:count,
                        end_seq:count) &priority=-5
    {
        local rec: TCPREORDERING::Info = [	
        	$ts   				 = timestamp, 
                $uid  				 = c$uid,
                $id   				 = c$id,
                $label				 = "TCP::Reordering",
                $seq  				 = seq,
                $gap  				 = gap,
                $segments_outoforder             = num_seq,
                $orig 				 = is_orig,
                $ambiguous			 = T,
                $nnseq 				 = o_seq ];
        Log::write(TCPREORDERING::LOG, rec);
    }
