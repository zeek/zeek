# $Id: interconn.bro 3997 2007-02-23 00:31:19Z vern $
#
# interconn - generic detection of interactive connections.

@load port-name
@load demux

# The following must be defined for the event engine to generate
# interconn events.
redef interconn_min_interarrival = 0.01 sec;
redef interconn_max_interarrival = 2.0 sec;
redef interconn_max_keystroke_pkt_size = 20;
redef interconn_default_pkt_size = 512;
redef interconn_stat_period = 15.0 sec;
redef interconn_stat_backoff = 1.5;

const interconn_min_num_pkts = 10 &redef; # min num of pkts sent
const interconn_min_duration = 2.0 sec &redef; # min duration for the connection

const interconn_ssh_len_disabled = T &redef;
const interconn_min_ssh_pkts_ratio = 0.6 &redef;

const interconn_min_bytes = 10 &redef;
const interconn_min_7bit_ascii_ratio = 0.75 &redef;

const interconn_min_num_lines = 2 &redef;
const interconn_min_normal_line_ratio = 0.5 &redef;

# alpha: portion of interarrival times within range
#	[interconn_min_interarrival, interconn_max_interarrival]
#
#	alpha should be >= interconn_min_alpha
#
# gamma: num_keystrokes_two_in_row / num_pkts
#	gamma indicates the portion of keystrokes in the overall traffic
#
#	gamma should be >= interconn_min_gamma

const interconn_min_alpha = 0.2 &redef; # minimum required alpha
const interconn_min_gamma = 0.2 &redef; # minimum required gamma

const interconn_standard_ports = { telnet, rlogin, ftp, ssh, smtp, 143/tcp, 110/tcp  } &redef;
const interconn_ignore_standard_ports = F &redef;

const interconn_demux_disabled = T &redef;

const INTERCONN_UNKNOWN = 0;	# direction/interactivity is unknown

const INTERCONN_FORWARD = 1;	# forward: a conn's orig is true originator
const INTERCONN_BACKWARD = 2;	# backward: a conn's resp is true originator

const INTERCONN_INTERACTIVE = 1;	# a conn is interactive
const INTERCONN_STANDARD_PORT = 2;	# conn involves a standard port to ignore

type conn_info : record {
	interactive: count; # interactivity: unknown/interactive/standard_port
	dir: count; # direction: unknown/forward/backward
};

global interconn_conns: table [conn_id] of conn_info; # table for all connections

# Table for resp_endp's of those established (non-partial) conn's.
# If a partial conn connects to one of such resp's, we can infer
# its direction.
global interconn_resps: table [addr, port] of count &default = 0;

global interconn_log = open_log_file("interconn") &redef;

global num_interconns = 0;

function interconn_conn_string(c: connection): string
	{
	return fmt("%.6f %s.%d > %s.%d",
		c$start_time,
		c$id$orig_h, c$id$orig_p,
		c$id$resp_h, c$id$resp_p);
	}

function interconn_weird(c: connection, s: string)
	{
	print fmt("%s interconn_weird: %s %s", network_time(), interconn_conn_string(c), s);
	}

function get_direction(c: connection): count
	{
	local id = c$id;

	if ( interconn_conns[id]$dir != INTERCONN_UNKNOWN )
		return interconn_conns[id]$dir;

	# The connection is not established yet, but one endpoint
	# is a known resp_endp
	if ( [id$resp_h, id$resp_p] in interconn_resps )
		{
		interconn_conns[id]$dir = INTERCONN_FORWARD;
		++interconn_resps[id$resp_h, id$resp_p];

		return INTERCONN_FORWARD;
		}

	else if ( [id$orig_h, id$orig_p] in interconn_resps )
		{
		interconn_conns[id]$dir = INTERCONN_BACKWARD;
		++interconn_resps[id$orig_h, id$orig_p];

		return INTERCONN_BACKWARD;
		}

	return INTERCONN_UNKNOWN;
	}

function comp_gamma(s: interconn_endp_stats): double
	{
	return s$num_pkts >= interconn_min_num_pkts ?
		(1.0 * s$num_keystrokes_two_in_row) / s$num_pkts : 0.0;
	}

function comp_alpha(s: interconn_endp_stats) : double
	{
	return ( s$num_keystrokes_two_in_row > 0 ) ?
		(1.0 * s$num_normal_interarrivals / s$num_keystrokes_two_in_row) : 0.0;
	}

function skip_further_interconn_processing(c: connection)
	{
	# This used to call skip_further_processing()
	# (if active_connection(c$id) returned T).  But that's
	# clearly wrong *if* we're also doing additional analysis
	# on the connection.  So do nothing.
	}

function log_interconn(c: connection, tag: string)
	{
	print interconn_log, fmt("%s %s", interconn_conn_string(c), tag);

	local id = c$id;

	if ( interconn_demux_disabled )
		skip_further_interconn_processing(c);
	else
		demux_conn(id, tag, "orig", "resp");
	}

function is_interactive_endp(s: interconn_endp_stats): bool
	{
	# Criteria 1: num_pkts >= interconn_min_num_pkts.
	if ( s$num_pkts < interconn_min_num_pkts )
		return F;

	# Criteria 2: gamma >= interconn_min_gamma.
	if ( comp_gamma(s) < interconn_min_gamma )
		return F;

	# Criteria 3: alpha >= interconn_min_alpha.
	if ( comp_alpha(s) < interconn_min_alpha )
		return F;

	return T;
	}

event connection_established(c: connection)
	{
	local id = c$id;
	local dir = interconn_conns[id]$dir;

	if ( dir == INTERCONN_FORWARD )
		return;

	if ( dir == INTERCONN_BACKWARD )
		{
		interconn_weird(c, "inconsistent direction");
		return;
		}

	interconn_conns[id]$dir = INTERCONN_FORWARD;
	++interconn_resps[id$resp_h, id$resp_p];
	}

event new_connection(c: connection)
	{
	local id = c$id;

	local info: conn_info;
	info$dir = INTERCONN_UNKNOWN;

	if ( interconn_ignore_standard_ports &&
	     (id$orig_p in interconn_standard_ports ||
	      id$resp_p in interconn_standard_ports) )
		{
		info$interactive = INTERCONN_STANDARD_PORT;
		skip_further_interconn_processing(c);
		}

	else
		info$interactive = INTERCONN_UNKNOWN;

	interconn_conns[id] = info;
	}

event interconn_remove_conn(c: connection)
	{
	local id = c$id;

	if ( id !in interconn_conns )
		# This can happen for weird connections such as those
		# with an initial SYN+FIN packet.
		return;

	local dir = interconn_conns[id]$dir;

	delete interconn_conns[id];
	delete demuxed_conn[c$id];

	if ( dir == INTERCONN_FORWARD )
		{
		if ( --interconn_resps[id$resp_h, id$resp_p] == 0 )
			delete interconn_resps[id$resp_h, id$resp_p];
		}

	else if ( dir == INTERCONN_BACKWARD )
		{
		if ( --interconn_resps[id$orig_h, id$orig_p] == 0 )
			delete interconn_resps[id$orig_h, id$orig_p];
		}
	}

event interconn_stats(c: connection,
			os: interconn_endp_stats, rs: interconn_endp_stats)
	{
	local id = c$id;

	if ( id !in interconn_conns )
		return;

	if ( interconn_conns[id]$interactive != INTERCONN_UNKNOWN )
		return; # already classified

	if ( c$duration < interconn_min_duration )
		# forget about excessively short connections
		return;

	local dir = get_direction(c);

	# Criteria:
	#
	#	if ( dir == FORWARD )
	#		(os) is interactive
	#	else if ( dir == BACKWARD )
	#		(rs) is interactive
	#	else
	#		either (os) or (rs) is interactive
	if ( dir == INTERCONN_FORWARD )
		{
		if ( ! is_interactive_endp(os) )
			return;
		}

	else if ( dir == INTERCONN_BACKWARD )
		{
		if ( ! is_interactive_endp(rs) )
			return;
		}

	else
		{
		if ( ! is_interactive_endp(os) && ! is_interactive_endp(rs) )
			return;
		}

	local tag: string;

	if ( ! interconn_ssh_len_disabled && (os$is_partial || rs$is_partial) )
		{
		local num_pkts = os$num_pkts + rs$num_pkts;
		local num_8k0_pkts = os$num_8k0_pkts + rs$num_8k0_pkts;
		local num_8k4_pkts = os$num_8k4_pkts + rs$num_8k4_pkts;

		if ( num_8k0_pkts > num_pkts * interconn_min_ssh_pkts_ratio )
			{
			# c now considered as interactive.
			interconn_conns[id]$interactive = INTERCONN_INTERACTIVE;
			tag = fmt("interconn.%d.ssh2", ++num_interconns);
			}
		else if ( num_8k4_pkts > num_pkts * interconn_min_ssh_pkts_ratio )
			{
			# c now considered as interactive.
			interconn_conns[id]$interactive = INTERCONN_INTERACTIVE;
			tag = fmt("interconn.%d.ssh1", ++num_interconns);
			}
		}

	# Criteria 4:	num_7bit_ascii / num_bytes is big enough; AND
	#		enough number of normal lines
	if ( interconn_conns[id]$interactive != INTERCONN_INTERACTIVE )
		{
		local num_bytes = os$num_bytes + rs$num_bytes;
		local num_7bit_ascii = os$num_7bit_ascii + rs$num_7bit_ascii;

		if ( num_bytes < interconn_min_bytes ||
		     num_7bit_ascii < num_bytes * interconn_min_7bit_ascii_ratio )
			return;

		local num_lines = os$num_lines + rs$num_lines;
		local num_normal_lines = os$num_normal_lines +
					 rs$num_normal_lines;

		if ( num_lines < interconn_min_num_lines ||
		     num_normal_lines < num_lines * interconn_min_normal_line_ratio )
			return;

		# c now considered as interactive.
		interconn_conns[id]$interactive = INTERCONN_INTERACTIVE;

		tag = fmt("interconn.%d", ++num_interconns);
		}

	log_interconn(c, tag);
	}
