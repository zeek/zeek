# Bro Lite base configuration file.

# General policy - these scripts are more infrastructural than service
# oriented, so in general avoid changing anything here.

@load site	# defines local and neighbor networks from static config
@load tcp	# initialize BPF filter for SYN/FIN/RST TCP packets
@load weird	# initialize generic mechanism for unusual events
@load conn	# access and record connection events
@load hot	# defines certain forms of sensitive access
@load frag	# process TCP fragments
@load print-resources	# on exit, print resource usage information

# Scan detection policy.
@load scan	# generic scan detection mechanism
@load trw	# additional, more sensitive scan detection
#@load drop	# include if installation has ability to drop hostile remotes

# Application level policy - these scripts operate on the specific service.
@load http	# general http analyzer, low level of detail
@load http-request	# detailed analysis of http requests
@load http-reply	# detailed analysis of http reply's

# Track software versions; required for some signature matching.  Also
# can be used by http and ftp policies.
@load software

@load ftp	# FTP analysis
@load portmapper	# record and analyze RPC portmapper requests
@load tftp	# identify and log TFTP sessions
@load login	# rlogin/telnet analyzer
@load irc	# IRC analyzer
@load blaster	# blaster worm detection
@load stepping	# "stepping stone" detection
@load synflood	# synflood attacks detection
@load smtp	# record and analyze email traffic - somewhat expensive

@load notice-policy	# tuning of notices to downgrade some alarms

# off by default
#@load icmp	# icmp analysis

# Tuning of memory consumption.
@load inactivity	# time out connections for certain services more quickly
# @load print-globals	# on exit, print the size of global script variables

# Record system statistics to the notice file
@load stats

# udp analysis - potentially expensive, depending on a site's traffic profile
#@load udp.all
#@load remove-multicast

# Prints the pcap filter and immediately exits.  Not used during
# normal operation.
#@load print-filter

## End policy script loading.

## General configuration.

@load rotate-logs
redef log_rotate_base_time = "0:00";
redef log_rotate_interval = 24 hr;


# Set additional policy prefixes.
@prefixes += lite

## End basic configuration.


## Scan configuration.
@ifdef ( Scan::analyze_all_services )
	redef Scan::analyze_all_services = T;

	# The following turns off scan detection.
	#redef Scan::suppress_scan_checks = T;

	# Be a bit more aggressive than default (though the defaults
	# themselves should be fixed).
	redef Scan::report_outbound_peer_scan = { 100, 1000, };

	# These services are skipped for scan detection due to excessive
	# background noise.
	redef Scan::skip_services += {
		http,           # Avoid Code Red etc. overload
		27374/tcp,      # Massive scanning in Jan 2002
		1214/tcp,       # KaZaa scans
		12345/tcp,      # Massive scanning in Apr 2002
		445/tcp,        # Massive distributed scanning Oct 2002
		135/tcp,        # These days, NetBIOS scanning is endemic
		137/udp,	# NetBIOS
		139/tcp,	# NetBIOS
		1025/tcp,
		6129/tcp,       # Dameware
		3127/tcp,       # MyDoom worms worms worms!
		2745/tcp,       # Bagel worm
		1433/tcp,       # Distributed scanning, April 2004
		5000/tcp,       # Distributed scanning, May 2004
		5554/tcp,       # More worm food, May 2004
		9898/tcp,       # Worms attacking worms. ugh - May 2004
		3410/tcp,       # More worm food, June 2004
		3140/tcp,       # Dyslexic worm food, June 2004
		27347/tcp,      # Can't kids type anymore?
		1023/tcp,       # Massive scanning, July 2004
		17300/tcp,      # Massive scanning, July 2004
	};

@endif

@ifdef ( ICMP::detect_scans )
	# Whether to detect ICMP scans.
	redef ICMP::detect_scans = F;
	redef ICMP::scan_threshold = 100;
@endif

@ifdef ( TRW::TRWAddressScan )
	# remove logging TRW scan events
	redef notice_action_filters += {
		[TRW::TRWAddressScan] = ignore_notice,
	};
@endif

# Note: default scan configuration is conservative in terms of memory use and
# might miss slow scans. Consider uncommenting these based on your sites scan
# traffic.
#redef distinct_peers &create_expire = 30 mins;
#redef distinct_ports &create_expire = 30 mins;
#redef distinct_low_ports &create_expire= 30 mins;


## End scan configuration.

## additional IRC checks
redef IRC::hot_words += /.*exe/ ;


## Dynamic Protocol Detection configuration
#
# This is off by default, as it requires a more powerful Bro host.
# Uncomment next line to activate.
# const use_dpd = T;

@ifdef ( use_dpd )
	@load dpd
	@load irc-bot
	@load dyn-disable
	@load detect-protocols
	@load detect-protocols-http
	@load proxy
	@load ssh

	# By default, DPD looks at all traffic except port 80.
	# For lightly loaded networks, comment out the restrict_filters line.
	# For heavily loaded networks, try adding addition ports (e.g., 25) to
	#   the restrict filters.
	redef capture_filters += [ ["tcp"] = "tcp" ];
	redef restrict_filters += [ ["not-http"] = "not (port 80)" ];
@endif

@ifdef ( ProtocolDetector::ServerFound )
# Report servers on non-standard ports only for local addresses.
redef notice_policy += {
	[$pred(a: notice_info) =
		{ return a$note == ProtocolDetector::ServerFound &&
					! is_local_addr(a$src); },
	 $result = NOTICE_FILE,
	 $priority = 1],

	# Report protocols on non-standard ports only for local addresses
	# (unless it's IRC).
	[$pred(a: notice_info) =
		{ return a$note == ProtocolDetector::ProtocolFound &&
					! is_local_addr(a$dst) &&
					a$sub != "IRC"; },
	 $result = NOTICE_FILE,
	 $priority = 1],
};
@endif

# The following is used to transfer state between Bro's when one
# takes over from another.
#
# NOTE: not implemented in the production version, so ignored for now.
@ifdef ( remote_peers_clear )
	redef remote_peers_clear += {
		[127.0.0.1, 55555/tcp] = [$hand_over = T],
		[127.0.0.1, 0/tcp] = [$hand_over = T]
	};
@endif

# Use tagged log files for alarms and notices.
redef use_tagging = T;

