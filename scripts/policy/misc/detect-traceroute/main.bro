##! This script detects large number of ICMP Time Exceeded messages heading
##! toward hosts that have sent low TTL packets.
##! It generates a notice when the number of ICMP Time Exceeded 
##! messages for a source-destination pair exceeds threshold
@load base/frameworks/measurement
@load base/frameworks/signatures
@load-sigs ./detect-low-ttls.sig

redef Signatures::ignored_ids += /traceroute-detector.*/;

module Traceroute;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## Indicates that a host was seen running traceroutes.  For more
		## detail about specific traceroutes that we run, refer to the
		## traceroute.log.
		Detected
	};

	## By default this script requires that any host detected running traceroutes
	## first send low TTL packets (TTL < 10) to the traceroute destination host.
	## Changing this this setting to `F` will relax the detection a bit by 
	## solely relying on ICMP time-exceeded messages to detect traceroute.
	const require_low_ttl_packets = T &redef;
	
	## Defines the threshold for ICMP Time Exceeded messages for a src-dst pair.
	## This threshold only comes into play after a host is found to be
	## sending low ttl packets.
	const icmp_time_exceeded_threshold = 3 &redef;

	## Interval at which to watch for the
	## :bro:id:`ICMPTimeExceeded::icmp_time_exceeded_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const icmp_time_exceeded_interval = 3min &redef;

	## The log record for the traceroute log.
	type Info: record {
		## Timestamp
		ts:   time &log;
		## Address initiaing the traceroute.
		src:  addr &log;
		## Destination address of the traceroute.
		dst:  addr &log;
	};

	global log_traceroute: event(rec: Traceroute::Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(Traceroute::LOG, [$columns=Info, $ev=log_traceroute]);

	local r1: Measurement::Reducer = [$stream="traceroute.time_exceeded", $apply=set(Measurement::UNIQUE)];
	local r2: Measurement::Reducer = [$stream="traceroute.low_ttl_packet", $apply=set(Measurement::SUM)];
	Measurement::create([$epoch=icmp_time_exceeded_interval,
	                     $reducers=set(r1, r2),
	                     $threshold_val(key: Measurement::Key, result: Measurement::Result) =
	                     	{
	                     	# Give a threshold value of zero depending on if the host 
	                     	# sends a low ttl packet.
	                     	if ( require_low_ttl_packets && result["traceroute.low_ttl_packet"]$sum == 0 )
	                     		return 0;
	                     	else
	                     		return result["traceroute.time_exceeded"]$unique;
	                     	},
	                     $threshold=icmp_time_exceeded_threshold,
	                     $threshold_crossed(key: Measurement::Key, result: Measurement::Result) =
	                     	{
	                     	local parts = split1(key$str, /-/);
	                     	local src = to_addr(parts[1]);
	                     	local dst = to_addr(parts[2]);
	                     	Log::write(LOG, [$ts=network_time(), $src=src, $dst=dst]);
	                     	NOTICE([$note=Traceroute::Detected,
	                     	        $msg=fmt("%s seems to be running traceroute", src),
	                     	        $src=src, $dst=dst,
	                     	        $identifier=cat(src)]);
	                     	}]);
	}

# Low TTL packets are detected with a signature.
event signature_match(state: signature_state, msg: string, data: string)
	{
	if ( state$sig_id == /traceroute-detector.*/ )
		Measurement::add_data("traceroute.low_ttl_packet", [$str=cat(state$conn$id$orig_h,"-",state$conn$id$resp_h)], [$num=1]);
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	Measurement::add_data("traceroute.time_exceeded", [$str=cat(context$id$orig_h,"-",context$id$resp_h)], [$str=cat(c$id$orig_h)]);
	}
