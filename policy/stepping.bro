# $Id: stepping.bro 6481 2008-12-15 00:47:57Z vern $

@load notice
@load port-name
@load demux
@load login
@load alarm

module Stepping;

export {
	redef enum Notice += {
		# A stepping stone was seen in which the first part of
		# the chain is a clear-text connection but the second part
		# is encrypted.  This often means that a password or
		# passphrase has been exposed in the clear, and may also
		# mean that the user has an incomplete notion that their
		# connection is protected from eavesdropping.
		ClearToEncrypted_SS,
	};
}

global step_log = open_log_file("step") &redef;

# The following must be defined for the event engine to generate
# stepping stone events.
redef stp_delta = 0.08 sec;
redef stp_idle_min = 0.5 sec;

global stepping_stone: event(c1: connection, c2: connection, method: string);

#### First, tag-based schemes - $DISPLAY, Last Login ####

# If <conn> was a login to <dst> propagating a $DISPLAY of <display>,
# then we make an entry of [<dst>, <display>] = <conn>.
global display_pairs: table[addr, string] of connection;

# Maps login tags like "Last login ..." to connections.
global tag_to_conn_map: table[string] of connection;

type tag_info: record {
	display: string;	# $DISPLAY, if any
	tag: string;		# login tag, e.g. "Last login ..."
};

global conn_tag_info: table[conn_id] of tag_info;

const STONE_DISPLAY = 1;
const STONE_LOGIN_BANNER = 2;
const STONE_TIMING = 4;
### fixme
global detected_stones: table[addr, port, addr, port, addr, port, addr, port]
	of count &default = 0;
global did_stone_summary: table[addr, port, addr, port, addr, port, addr, port]
	of count &default = 0;

function new_tag_info(c: connection)
	{
	local ti: tag_info;
	ti$tag = ti$display = "";
	conn_tag_info[c$id] = ti;
	}

event login_display(c: connection, display: string)
	{
	local id = c$id;
	if ( id !in conn_tag_info )
		new_tag_info(c);

	conn_tag_info[id]$display = display;
	display_pairs[id$resp_h, display] = c;

	if ( [id$orig_h, display] in display_pairs )
		event Stepping::stepping_stone(display_pairs[id$orig_h, display], c, "display");
	}

event login_output_line(c: connection, line: string)
	{
	if  ( /^([Ll]ast +(successful)? *login)/ | /^Last interactive login/
	     !in line ||
	      # Some finger output includes "Last login ..." but luckily
	      # appears to be terminated by ctrl-A.
	      /\001/ in line )
		return;

	if ( c$id !in conn_tag_info )
		new_tag_info(c);

	local ti = conn_tag_info[c$id];
	local tag = line;

	if ( ti$tag == "" )
		ti$tag = tag;

	if ( tag in tag_to_conn_map )
		{
		local c2 = tag_to_conn_map[tag];

		### Would really like this taken care of by having
		# tag_to_conn_map[tag] deleted when c2 goes away.
		if ( active_connection(c2$id) )
			event Stepping::stepping_stone(c2, c, "login-tag");
		}
	else
		tag_to_conn_map[tag] = c;
	}

event connection_finished(c: connection)
	{
	### would really like some automatic destructors invoked
	### whenever a connection goes away
	local id = c$id;
	if ( id in conn_tag_info )
		{
		local ti = conn_tag_info[id];
		delete display_pairs[id$resp_h, ti$display];
		delete tag_to_conn_map[ti$tag];
		delete conn_tag_info[id];
		}
	}


#### Now, timing-based correlation ####

const stp_ratio_thresh = 0.3 &redef;	# prop. of idle times that must coincide

# Time scale to which following thresholds apply.
const stp_scale =  100.0 &redef;

const stp_common_host_thresh = 2 &redef; # must be <= stp_random_pair_thresh
const stp_random_pair_thresh = 4 &redef;

const stp_demux_disabled = T &redef;

# Indexed by the center host (or destination of the first connection,
# for ABCD stepping stones) and the $addl information associated with
# the connection (i.e., often username).  If present in the set, then
# we shouldn't bother generating a report for a clear->ssh stepping stone.
const skip_clear_ssh_reports: set[addr, string] &redef;

global num_stp_pairs = 0;

type endp_info: record {
	conn: connection;
	id: conn_id;
	resume_time: time; # time when resuming from most recent idle period
	old_resume_time: time; # time when resuming from penultimate idle period
	idle_cnt: count; # number of idle periods for this endpoint (flow)
};

type pair_info: record {
	is_stp: bool; # true if flow pair considered a stepping stone pair
	hit: count; # number of coincidences
	hit_two_in_row: count; # number of coincidences two-in-row
};

# For connection k:
#	stp_endps[2k] is the orig endpoint
#	stp_endps[2k+1] is the resp endpoint
global stp_endps: table[int] of endp_info;

# Some endpoint pairs are weird, e.g., when two endp's share a common port.
# Such weird endp pairs may be correlated, but are unlikely to be stepping
# stone pairs.
global stp_weird_pairs: set[int, int];

# Normal (i.e., not weird) endp pairs.
global stp_normal_pairs: table[int, int] of pair_info;

function is_orig(e: int): bool
	{
	return (e % 2) == 0;
	}

function peer(e: int): int
	{
	return (e % 2) == 0 ? (e + 1): (e - 1);
	}

function orig_host(e: int): addr
	{
	return stp_endps[e]$id$orig_h;
	}

function resp_host(e: int): addr
	{
	return stp_endps[e]$id$resp_h;
	}

function orig_port(e: int): port
	{
	return stp_endps[e]$id$orig_p;
	}

function resp_port(e: int): port
	{
	return stp_endps[e]$id$resp_p;
	}

function build_conn(e: int): connection
	{ # return the id of the orig, not the resp
	return stp_endps[e]$conn;
	}

function stp_id_string(id: conn_id): string
	{
	return fmt("%s.%d > %s.%d", id$orig_h, id$orig_p, id$resp_h, id$resp_p);
	}

function stp_create_weird_pair(e1: int, e2: int)
	{
	add stp_weird_pairs[e1, e2];
	}

function stp_create_normal_pair(e1: int, e2: int)
	{
	local pair: pair_info;

	pair$is_stp = F;
	pair$hit = pair$hit_two_in_row = 0;

	stp_normal_pairs[e1, e2] = pair;
	}

function stp_correlate_weird_pair(e1: int, e2: int)
	{ # do nothing right now
	}

global stp_check_normal_pair: function(e1: int, e2: int): bool;

function stp_correlate_normal_pair(e1: int, e2: int)
	{
	if ( stp_normal_pairs[e1, e2]$is_stp )
		return; # already classified as stepping stone pair

	++stp_normal_pairs[e1, e2]$hit;

	if ( stp_endps[e1]$old_resume_time != 0.0 &&
	     stp_endps[e2]$old_resume_time != 0.0 )
		{
		local dt = stp_endps[e2]$old_resume_time -
			   stp_endps[e1]$old_resume_time;
		if ( dt >= 0.0 sec && dt <= stp_delta )
			++stp_normal_pairs[e1, e2]$hit_two_in_row;
		}
	stp_check_normal_pair(e1, e2);
	}

function stp_check_weird_pair(e1: int, e2: int)
	{ # do nothing right now
	}

function stp_check_normal_pair(e1: int, e2: int): bool
	{
	if ( stp_normal_pairs[e1, e2]$is_stp )
		return T; # already classified as stepping stone pair

	local p1 = peer(e1);
	local p2 = peer(e2);
	local reverse_exists = [p2, p1] in stp_normal_pairs;

	if ( reverse_exists && stp_normal_pairs[p2, p1]$is_stp )
		{ # already classified as stepping stone pair
		stp_normal_pairs[e1, e2]$is_stp = T;
		return T;
		}

	local hit_two_in_row = stp_normal_pairs[e1, e2]$hit_two_in_row;
	if ( reverse_exists )
		hit_two_in_row = hit_two_in_row +
				stp_normal_pairs[p2, p1]$hit_two_in_row;

	# Criteria 1:
	#	if ( e1 and e2 share a common host )
	#		hit_two_in_row >= stp_common_host_thresh
	#	else
	#		hit_two_in_row >= stp_random_pair_thresh

	local factor = max_double(1.0,
				min_count(stp_endps[e1]$idle_cnt,
					  stp_endps[e2]$idle_cnt) / stp_scale);

	if ( hit_two_in_row < factor * stp_common_host_thresh )
		return F;

	if ( hit_two_in_row < factor * stp_random_pair_thresh &&
	     orig_host(e1) != orig_host(e2) && orig_host(e1) != resp_host(e2) &&
	     resp_host(e1) != orig_host(e2) && resp_host(e1) != resp_host(e2) )
		return F;

	# Criteria 2:
	#	hit_ratio >= stp_ratio_thresh

	local hit_ratio: double;
	if ( reverse_exists &&
	     stp_normal_pairs[p2, p1]$hit > stp_normal_pairs[e1, e2]$hit )
		hit_ratio = (1.0 * stp_normal_pairs[p2, p1]$hit) /
				min_count(stp_endps[p1]$idle_cnt,
					  stp_endps[p2]$idle_cnt);
	else
		hit_ratio = (1.0 * stp_normal_pairs[e1, e2]$hit) /
				min_count(stp_endps[e1]$idle_cnt,
					  stp_endps[e2]$idle_cnt);

	if ( hit_ratio < stp_ratio_thresh )
		return F;

	stp_normal_pairs[e1, e2]$is_stp = T;
	event Stepping::stepping_stone(build_conn(e1), build_conn(e2), "timing");

	return T;
	}

function reverse_id(id: conn_id): conn_id
	{
	local rid: conn_id;

	rid$orig_h = id$resp_h;
	rid$orig_p = id$resp_p;
	rid$resp_h = id$orig_h;
	rid$resp_p = id$orig_p;

	return rid;
	}

event stp_create_endp(c: connection, e: int, is_orig: bool)
	{
	local end_i: endp_info;

	end_i$conn = c;
	end_i$id = is_orig ? c$id : reverse_id(c$id);
	end_i$resume_time = end_i$old_resume_time = 0.0;
	end_i$idle_cnt = 0;

	stp_endps[e] = end_i;
	}

event stp_resume_endp(e: int)
	{
	stp_endps[e]$old_resume_time = stp_endps[e]$resume_time;
	stp_endps[e]$resume_time = network_time();
	++stp_endps[e]$idle_cnt;
	}

event stp_correlate_pair(e1: int, e2: int)
	{
	local normal = T;

	if ( [e1, e2] in stp_normal_pairs )
		;

	else if ( [e1, e2] in stp_weird_pairs )
		normal = F;

	else
		{
		# An endpoint pair is considered weird, iff:
		#	the two flows both originated at same host, or
		#	both terminated at same host, or
		#	at least one flow is within a single host, or
		#	two flows share an endpoint (host, port)

		if ( orig_host(e1) == orig_host(e2) || resp_host(e1) == resp_host(e2) ||
		     orig_host(e1) == resp_host(e1) || orig_host(e2) == resp_host(e2) ||
		     (orig_host(e1) == resp_host(e2) && orig_port(e1) == resp_port(e2)) ||
		     (resp_host(e1) == orig_host(e2) && resp_port(e1) == orig_port(e2)) )
			{
			stp_create_weird_pair(e1, e2);
			normal = F;
			}
		else
			stp_create_normal_pair(e1, e2);
		}

	if ( normal )
		stp_correlate_normal_pair(e1, e2);
	else
		stp_correlate_weird_pair(e1, e2);
	}

event stp_remove_pair(e1: int, e2: int)
	{
	delete stp_normal_pairs[e1, e2];
	delete stp_weird_pairs[e1, e2];
	}

event stp_remove_endp(e: int)
	{
	delete stp_endps[e];
	}


function report_stone(id1: conn_id, addl1: string, id2: conn_id, addl2: string)
: string
	{
	if ( id1$resp_h == id2$orig_h )
		# A single-intermediary stepping stone.
		return fmt("%s -> %s %s-> %s %s",
				id1$orig_h,
				endpoint_id(id1$resp_h, id1$resp_p), addl1,
				endpoint_id(id2$resp_h, id2$resp_p), addl2);
	else
		# A multi-intermediary stepping stone.
		return fmt("%s -> %s %s... %s -> %s %s",
				id1$orig_h,
				endpoint_id(id1$resp_h, id1$resp_p), addl1,
				id2$orig_h,
				endpoint_id(id2$resp_h, id2$resp_p), addl2);
	}

event stone_summary(id1: conn_id, id2: conn_id)
	{
	if ( ++did_stone_summary[id1$orig_h, id1$orig_p, id1$resp_h, id1$resp_p, id2$orig_h, id2$orig_p, id2$resp_h, id2$resp_p] > 1 )
		return;

	local detection_type = detected_stones[id1$orig_h, id1$orig_p, id1$resp_h, id1$resp_p, id2$orig_h, id2$orig_p, id2$resp_h, id2$resp_p];

	local report: string;

	if ( detection_type == STONE_DISPLAY )
		report = "only-display";
	else if ( detection_type == STONE_LOGIN_BANNER )
		report = "only-banner";
	else if ( detection_type == STONE_TIMING )
		report = "only-timing";
	else if ( detection_type == STONE_LOGIN_BANNER + STONE_TIMING )
		report = "stone-both";
	else
		report = fmt("stone-other-%d", detection_type);

	print step_log, fmt("%s detected %s %s %d %s %d %s %d %s %d",
		network_time(), report, id1$orig_h, id1$orig_p, id1$resp_h,
		id1$resp_p, id2$orig_h, id2$orig_p, id2$resp_h, id2$resp_p);
	}

event stepping_stone(c1: connection, c2: connection, method: string)
	{
	# Put into canonical form: make #1 be the earlier of the two
	# connections.
	local id1 = c1$start_time < c2$start_time ? c1$id : c2$id;
	local id2 = c1$start_time < c2$start_time ? c2$id : c1$id;

	local addl1 = c1$start_time < c2$start_time ? c1$addl : c2$addl;
	local addl2 = c1$start_time < c2$start_time ? c2$addl : c1$addl;

	if ( id1$orig_h == id2$orig_h || id1$resp_h == id2$resp_h )
		# of the form A->B, A->C ; or B->A, C->A ; uninteresting.
		return;

	local tag = fmt("stp.%d", ++num_stp_pairs);
	local prelude = fmt("%.6f step %s (%s)", network_time(),  num_stp_pairs, method);

	local stone_type = (method == "display" ? STONE_DISPLAY :
				(method == "login-tag" ? STONE_LOGIN_BANNER :
					STONE_TIMING));

	local current_stones = detected_stones[id1$orig_h, id1$orig_p, id1$resp_h, id1$resp_p, id2$orig_h, id2$orig_p, id2$resp_h, id2$resp_p];

	if ( (current_stones / stone_type) % 2 == 0 )
		detected_stones[id1$orig_h, id1$orig_p, id1$resp_h, id1$resp_p, id2$orig_h, id2$orig_p, id2$resp_h, id2$resp_p] = current_stones + stone_type;

	schedule 1 day { stone_summary(id1, id2) };

	print step_log, fmt("%s: %s", prelude, report_stone(id1, addl1, id2, addl2));

	local is_ssh1 = id1$orig_p == ssh || id1$resp_p == ssh;
	local is_ssh2 = id2$orig_p == ssh || id2$resp_p == ssh;

	if ( ! is_ssh1 && is_ssh2 )
		{ # Inbound clear-text, outbound ssh.
		if ( [id1$resp_h, addl1] !in skip_clear_ssh_reports )
			NOTICE([$note=ClearToEncrypted_SS,
				# The following isn't sufficient for
				# A->(B->C)->D stepping stones, only A->B->C.
				$src=c1$id$orig_h, $conn=c2,
				$user=addl1, $sub=addl2,
				$msg=fmt("clear -> ssh: %s", report_stone(id1, addl1, id2, addl2))]);
		}

	if ( ! stp_demux_disabled )
		{
		demux_conn(id1, tag, "keys", "server");
		demux_conn(id2, tag, "keys", "server");
		}
	}
