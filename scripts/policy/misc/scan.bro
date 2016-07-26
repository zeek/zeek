##! TCP Scan detection.

# ..Authors: Sheharbano Khattak
#            Seth Hall
#            All the authors of the old scan.bro

@load base/frameworks/notice
@load base/frameworks/sumstats

@load base/utils/time

module Scan;

export {
	redef enum Notice::Type += {
		## Address scans detect that a host appears to be scanning some
		## number of destinations on a single port. This notice is
		## generated when more than :bro:id:`Scan::scan_threshold`
		## unique hosts are seen over the previous
		## :bro:id:`Scan::scan_interval` time range.
		Address_Scan,

		## Port scans detect that an attacking host appears to be
		## scanning a single victim host on several ports.  This notice
		## is generated when an attacking host attempts to connect to
		## :bro:id:`Scan::scan_threshold`
		## unique ports on a single host over the previous
		## :bro:id:`Scan::scan_interval` time range.
		Port_Scan,

		## Random scans detect that an attacking host appears to be
		## scanning multiple victim hosts on several ports.  This notice
		## is generated when an attacking host attempts to connect to
		## :bro:id:`Scan::scan_threshold`
		## unique hosts and ports over the previous
		## :bro:id:`Scan::scan_interval` time range.
		Random_Scan,
	};

	## Failed connection attempts are tracked over this time interval for
	## the address scan detection.  A higher interval will detect slower
	## scanners, but may also yield more false positives.
	const scan_interval = 5min &redef;

	## The threshold of the unique number of host+ports a scanning host has to
	## have failed connections with on
	const scan_threshold = 100.0 &redef;

	global Scan::scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
}

function analyze_unique_hostports(unique_vals: set[SumStats::Observation]): Notice::Info
{
	local victims: set[string];
	local ports: set[string];
	for ( s in unique_vals )
		{
		local parts = split_string(s$str, /\//);
		local victim = parts[0];
		local scanned_port = parts[1];
		add victims[victim];
		add ports[scanned_port];
		}
	
	if(|ports| == 1)
		{
		#Extract the single port
		for (p in ports)
			{
			return [$note=Address_Scan, $msg=fmt("%s unique hosts on port %s", |victims|, p), $p=to_port(cat(p, "/tcp"))];
			}
		}
	if(|ports| <= 5)
		{
		local ports_string = join_string_set(ports, ", ");
		return [$note=Address_Scan, $msg=fmt("%s unique hosts on ports %s", |victims|, ports_string)];
		}
	if(|victims| == 1)
		{
		#Extract the single victim
		for (v in victims)
			return [$note=Port_Scan, $msg=fmt("%s unique ports on host %s", |ports|, v)];
		}
	if(|victims| <= 5)
		{
		local victims_string = join_string_set(victims, ", ");
		return [$note=Port_Scan, $msg=fmt("on hosts %s", victims_string)];
		}
	return [$note=Random_Scan, $msg=fmt("%d hosts on %d ports", |victims|, |ports|)];
}

function generate_notice(key: SumStats::Key, result: SumStats::Result): Notice::Info
	{
	local r = result["scan.fail"];
	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	local dur = duration_to_mins_secs(r$end-r$begin);
	local n = analyze_unique_hostports(r$unique_vals);
	n$msg = fmt("%s scanned at least %s in %s", key$host, n$msg, dur);
	n$src = key$host;
	n$sub = side;
	n$identifier=cat(key$host);
	return n;
	}

event bro_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="scan.fail", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(scan_threshold+2)];
	SumStats::create([$name="scan",
	                  $epoch=scan_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local scale_factor = Site::is_local_addr(key$host) ? 0.1 : 1.0;
	                  	return (result["scan.fail"]$unique+0.0) * scale_factor;
	                  	},
	                  $threshold=scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local note = generate_notice(key, result);
	                  	NOTICE(note);
	                  	}]);
	}

function add_sumstats(id: conn_id)
	{
	local scanner      = id$orig_h;
	local victim       = id$resp_h;
	local scanned_port = id$resp_p;

	if ( hook Scan::scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.fail", [$host=scanner], [$str=cat(victim, "/", scanned_port)]);
	}

function is_failed_conn(c: connection): bool
	{
	# Sr || ( (hR || ShR) && (data not sent in any direction) )
	if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
	     (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
	       (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
	      ) && /[Dd]/ !in c$history )
	   )
		return T;
	return F;
	}

event connection_attempt(c: connection)
	{
	if ( "H" !in c$history )
		add_sumstats(c$id);
	}

event connection_rejected(c: connection)
	{
	if ( "S" in c$history )
		add_sumstats(c$id);
	}

event connection_reset(c: connection)
	{
	if ( is_failed_conn(c) )
		add_sumstats(c$id);
	}
