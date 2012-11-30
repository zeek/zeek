##! This script detects large number of ICMP Time Exceeded messages heading
##! toward hosts that have sent low TTL packets.
##! It generates a notice when the number of ICMP Time Exceeded 
##! messages for a source-destination pair exceeds threshold
@load base/frameworks/metrics
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
	const icmp_time_exceeded_interval = 1min &redef;

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

# Track hosts that have sent low TTL packets and which hosts they 
# sent them to.
global low_ttlers: set[addr, addr] = {} &create_expire=2min &synchronized;

function traceroute_detected(src: addr, dst: addr)
	{
	Log::write(LOG, [$ts=network_time(), $src=src, $dst=dst]);
	NOTICE([$note=Traceroute::Detected,
	        $msg=fmt("%s seems to be running traceroute", src),
	        $src=src, $dst=dst,
	        $identifier=cat(src)]);
	}


event bro_init() &priority=5
	{
	Log::create_stream(Traceroute::LOG, [$columns=Info, $ev=log_traceroute]);

	Metrics::add_filter("traceroute.time_exceeded", 
	                    [$log=F,
	                     $every=icmp_time_exceeded_interval,
	                     $measure=set(Metrics::UNIQUE),
	                     $threshold=icmp_time_exceeded_threshold,
	                     $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = {
	                     	local parts = split1(index$str, /-/);
	                     	local src = to_addr(parts[1]);
	                     	local dst = to_addr(parts[2]);
	                     	if ( require_low_ttl_packets )
	                     		{
	                     		when ( [src, dst] in low_ttlers )
	                     			{
	                     			traceroute_detected(src, dst);
		                     		}
		                     	}
                     		else
                     			traceroute_detected(src, dst);
	                     }]);
	}

# Low TTL packets are detected with a signature.
event signature_match(state: signature_state, msg: string, data: string)
	{
	if ( state$sig_id == /traceroute-detector.*/ )
		add low_ttlers[state$conn$id$orig_h, state$conn$id$resp_h];
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	Metrics::add_data("traceroute.time_exceeded", [$str=cat(context$id$orig_h,"-",context$id$resp_h)], [$str=cat(c$id$orig_h)]);
	}
