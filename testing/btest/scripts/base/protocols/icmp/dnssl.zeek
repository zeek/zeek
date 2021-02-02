# @TEST-EXEC: zeek -b -C -r $TRACES/icmp_nd_dnssl.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/conn

event icmp_router_advertisement(c: connection, icmp: icmp_info, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool,
                                pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval,
                                retrans_timer: interval, options: icmp6_nd_options ){
	for (i in options){
		if(options[i]$otype==31){
			print fmt("dnssl len %d payload %d",options[i]$len,|options[i]$payload|);
		}
	}
}
