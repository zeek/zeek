function state_string(c: int): string
	{
		local s = "UNKNOWN";
		if( c == 1 ) return "3WHS";
		if( c == 2 ) return "SS";
		if( c == 3 ) return "CA";
		if( c == 4 ) return "CLOSE";
		if( c == 5 ) return "LIMITED";
		if( c == 6 ) return "STEADY";
		if( c == 7 ) return "ZEROWINDOW";
		if( c == 8)  return "REPEATING";
		if( c == 9)  return "IDLE";
		return s;
	}

function rtxreason_string(c: int): string
	{
		local s = "UNKNOWN";
		if( c == 1 ) s = "PREV_OBSERVED";
		if( c == 2 ) s = "SPANS_PREV";
		if( c == 3 ) s = "PREV_ACKED";
		if( c == 4 ) s = "PARTIALLY_ACKED";
		if( c == 5 ) s = "TIMESTAMP";
		if( c == 6 ) s = "ACK";
		if( c == 7 ) s = "GAP";
		return s;
	}

function rtxrtype_string(c: int): string
	{
		local s = "UNKNOWN";
		if( c == 1 )  return "RTO";
		if( c == 2 )  return "FAST_3DUP";
		if( c == 3 )  return "FAST_SUSPECT";
		if( c == 4 )  return "EARLY_REXMIT";
		if( c == 5 )  return "REXMIT";
		if( c == 6 )  return "TESTING";
		if( c == 7 )  return "NO_RTT";
		if( c == 8 )  return "NO_TS";
		if( c == 9 )  return "SEGMENT_EARLY_REXMIT";
		if( c == 10 ) return "BYTE_EARLY_REXMIT";
		if( c == 11 ) return "SACK_SEGMENT_EARLY_REXMIT";
		if( c == 12 ) return "SACK_BYTE_EARLY_REXMIT";
		if( c == 13 ) return "SACK_BASED_RECOVERY";
		if( c == 14 ) return "BRUTE_FORCE_RTO";
		if( c == 15 ) return "RTO_NO_DUP_ACK";
		if( c == 16 ) return "FACK_BASED_RECOVERY";
		return s;
	}

function rexmit_primary_label(c: int): string
	{
        local s = "UNKNOWN";
        if( c == 1 )  return "RTO";                     #"RTO"
        if( c == 2 )  return "FASTRTX";                 #"FAST_3DUP"
        if( c == 3 )  return "FASTRTX";                 #"FAST_SUSPECT"
        if( c == 4 )  return "FASTRTX";                 #"EARLY_REXMIT"
        if( c == 5 )  return "REXMIT";                  #"REXMIT"
        if( c == 6 )  return "UNKNOWN";                 #"TESTING";
        if( c == 7 )  return "UNKNOWN";     		#"NO_RTT";
        if( c == 8 )  return "UNKNOWN";     		#"NO_TS";
        if( c == 9 )  return "FASTRTX";                 #"SEGMENT_EARLY_REXMIT"
        if( c == 10 ) return "FASTRTX";                	#"BYTE_EARLY_REXMIT"
        if( c == 11 ) return "FASTRTX";                	#"SACK_SEGMENT_EARLY_REXMIT"
        if( c == 12 ) return "FASTRTX";                	#"SACK_BYTE_EARLY_REXMIT"
        if( c == 13 ) return "FASTRTX";                	#"SACK_BASED_RECOVERY"
        if( c == 14 ) return "RTO";                    	#"BRUTE_FORCE_RTO"
        if( c == 15 ) return "RTO";                    	#"RTO_NO_DUP_ACK"
        if( c == 16 ) return "FACKRexmit";             	#"FACK_BASED_RECOVERY"
        return s;
	}
