##! This script handles core generated connection related "weird" events to
##! push weird information about connections into the weird framework.
##! For live operational deployments, this can frequently cause load issues
##! due to large numbers of these events and quite possibly shouldn't be
##! loaded.

@load base/frameworks/notice

module Conn;

export {
	redef enum Notice::Type += {
		## Possible evasion; usually just chud.
		Retransmission_Inconsistency,
		## Data has sequence hole; perhaps due to filtering.
		Content_Gap,
	};
}

event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
	{
	NOTICE([$note=Retransmission_Inconsistency,
	        $conn=c,
	        $msg=fmt("%s rexmit inconsistency (%s) (%s) [%s]",
	                 id_string(c$id), t1, t2, tcp_flags),
	        $identifier=fmt("%s", c$id)]);
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	NOTICE([$note=Content_Gap, $conn=c,
	        $msg=fmt("%s content gap (%s %d/%d)",
	                 id_string(c$id), is_orig ? ">" : "<", seq, length)]);
	}
