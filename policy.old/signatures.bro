# $Id: signatures.bro 4909 2007-09-24 02:26:36Z vern $

@load notice

redef enum Notice += {
	SensitiveSignature,	# generic for alarm-worthy
	MultipleSignatures,	# host has triggered many signatures
	MultipleSigResponders,	# host has triggered same signature on
				# multiple responders
	CountSignature,		# sig. has triggered mutliple times for a dest
	SignatureSummary,	# summarize # times a host triggered a signature
};

type SigAction: enum {
	SIG_IGNORE,	# ignore this sig. completely (even for scan detection)
	SIG_QUIET,	# process, but don't report individually
	SIG_FILE,	# write to signatures and notice files
	SIG_FILE_BUT_NO_SCAN,	# as SIG_FILE, but ignore for scan processing
	SIG_ALARM,	# alarm and write to signatures, notice, and alarm files
	SIG_ALARM_PER_ORIG, 	# alarm once per originator
	SIG_ALARM_ONCE, 	# alarm once and then never again
	SIG_ALARM_NO_WORM,	# alarm if not originated by a known worm-source
	SIG_COUNT_PER_RESP,	# count per dest. and alarm if threshold reached
	SIG_SUMMARY, 	# don't alarm, but generate per-orig summary
};

# Actions for a signature.
const signature_actions: table[string] of SigAction =  {
	["unspecified"] = SIG_IGNORE,	# place-holder
} &redef &default = SIG_ALARM;

type sig_info: record {
	note: Notice;			# notice associated with signature event
	src_addr: addr &optional;
	src_port: port &optional;
	dst_addr: addr &optional;
	dst_port: port &optional;
	sig_id: string &optional &default="";
	event_msg: string;
	sub_msg: string &optional;	# matched payload data or extra message
	sig_count: count &optional;	# num. sigs, usually from summary count
	host_count: count &optional;	# num. hosts, from a summary count
};

global sig_file = open_log_file("signatures");

global sig_summary_interval = 1 day &redef;

# Given a string, returns an escaped version suitable for being
# printed in the colon-separated notice format.  This means that
# (1) any colons are escaped using '\', and (2) any '\'s are
# likewise escaped.
function signature_escape(s: string): string
	{
	s = subst_string(s, "\\", "\\\\");
	return subst_string(s, ":", "\\:");
	}

# function call for writing to the signatures log file
function signature_file_write(s: sig_info)
	{
	local t = fmt("%.06f", network_time());
	local src_addr = s?$src_addr ? fmt("%s", s$src_addr) : "";
	local src_port = s?$src_port ? fmt("%s", s$src_port) : "";
	local dst_addr = s?$dst_addr ? fmt("%s", s$dst_addr) : "";
	local dst_port = s?$dst_port ? fmt("%s", s$dst_port) : "";
	local sub_msg = s?$sub_msg ? signature_escape(s$sub_msg) : "";
	local sig_count = s?$sig_count ? fmt("%s", s$sig_count) : "";
	local host_count = s?$host_count ? fmt("%s", s$host_count) : "";

	local info =
		fmt("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
			t, s$note, src_addr, src_port, dst_addr,
			dst_port, s$sig_id, s$event_msg, sub_msg,
			sig_count, host_count);

	print sig_file, info;
	}


# Scan detection.

# Alarm if, for a pair [orig, signature], the number of different responders
# has reached one of the thresholds.
const horiz_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;

# Alarm if, for a pair [orig, resp], the number of different signature matches
# has reached one of the thresholds.
const vert_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;

# Alarm if a SIG_COUNT_PER_RESP signature is triggered as often as given
# by one of these thresholds.
const count_thresholds = { 5, 10, 50, 100, 500, 1000, 10000, 1000000, } &redef;

type sig_set: set[string];
type addr_set: set[addr];

# We may need to define some &read_expires on these:
global horiz_table: table[addr, string] of addr_set &read_expire = 1 hr;
global vert_table: table[addr, addr] of sig_set &read_expire = 1 hr;
global last_hthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global last_vthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global count_per_resp: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global count_per_orig: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global did_sig_log: set[string] &read_expire = 1 hr;

event sig_summary(orig: addr, id: string, msg: string)
	{
@ifdef ( is_worm_infectee )
	if ( is_worm_infectee(orig) )
			return;
@endif

	NOTICE([$note=SignatureSummary, $src=orig,
		$filename=id, $msg=fmt("%s: %s", orig, msg),
		$n=count_per_orig[orig,id] ]);
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	local id = state$id;
	local action = signature_actions[id];

	if ( action == SIG_IGNORE )
		return;

	# We always add it to the connection record.
	append_addl(state$conn, state$id);

	# Trim the matched data down to something reasonable
	if ( byte_len(data) > 140 )
		data = fmt("%s...", sub_bytes(data, 0, 140));

	if ( action != SIG_QUIET && action != SIG_COUNT_PER_RESP )
		{
		if ( state$is_orig )
			{
			signature_file_write(
				[$note=SensitiveSignature,
				 $src_addr=state$conn$id$orig_h,
				 $src_port=state$conn$id$orig_p,
				 $dst_addr=state$conn$id$resp_h,
				 $dst_port=state$conn$id$resp_p,
				 $sig_id=state$id,
				 $event_msg=fmt("%s: %s", state$conn$id$orig_h, msg),
				 $sub_msg=data]);
			}
		else
			{
			signature_file_write(
				[$note=SensitiveSignature,
				 $src_addr=state$conn$id$resp_h,
				 $src_port=state$conn$id$resp_p,
				 $dst_addr=state$conn$id$orig_h,
				 $dst_port=state$conn$id$orig_p,
				 $sig_id=state$id,
				 $event_msg=fmt("%s: %s", state$conn$id$resp_h, msg),
				 $sub_msg=data]);
			}
		}

	local notice = F;

	if ( action == SIG_ALARM )
		notice = T;

@ifdef ( is_worm_infectee )
	if ( action == SIG_ALARM_NO_WORM &&
	     ! is_worm_infectee(state$conn$id$orig_h) )
		notice = T;
@endif

	if ( action == SIG_COUNT_PER_RESP )
		{
		local dst = state$conn$id$resp_h;
		if ( ++count_per_resp[dst,id] in count_thresholds )
			{
			NOTICE([$note=CountSignature, $conn=state$conn,
				   $msg=msg,
				   $filename=id,
				   $n=count_per_resp[dst,id],
				   $sub=fmt("%d matches of signature %s on host %s",
						count_per_resp[dst,id],
						state$id, dst)]);
			}
		}

	if ( (action == SIG_ALARM_PER_ORIG || action == SIG_SUMMARY) &&
	     ++count_per_orig[state$conn$id$orig_h, state$id] == 1 )
		{
		if ( action == SIG_ALARM_PER_ORIG )
			notice = T;
		else
			schedule sig_summary_interval
				{
				sig_summary(state$conn$id$orig_h, state$id, msg)
				};
		}

	if ( action == SIG_ALARM_ONCE )
		{
		if ( [state$id] !in did_sig_log )
			{
			notice = T;
			add did_sig_log[state$id];
			}
		}

	if ( notice )
		{
		local src_addr: addr;
		local src_port: port;
		local dst_addr: addr;
		local dst_port: port;

		if ( state$is_orig )
			{
			src_addr = state$conn$id$orig_h;
			src_port = state$conn$id$orig_p;
			dst_addr = state$conn$id$resp_h;
			dst_port = state$conn$id$resp_p;
			}
		else
			{
			src_addr = state$conn$id$resp_h;
			src_port = state$conn$id$resp_p;
			dst_addr = state$conn$id$orig_h;
			dst_port = state$conn$id$orig_p;
			}

		NOTICE([$note=SensitiveSignature,
			$conn=state$conn, $src=src_addr,
			$dst=dst_addr, $filename=id, $msg=fmt("%s: %s", src_addr, msg),
			$sub=data]);
		}

	if ( action == SIG_FILE_BUT_NO_SCAN || action == SIG_SUMMARY )
		return;

@ifdef ( is_worm_infectee )
	# Ignore scanning of known worm infectees.
	if ( is_worm_infectee(state$conn$id$orig_h) )
		return;
@endif

	# Keep track of scans.
	local orig = state$conn$id$orig_h;
	local resp = state$conn$id$resp_h;

	if ( [orig, id] !in horiz_table )
		horiz_table[orig, id] = set();

	add horiz_table[orig, id][resp];

	if ( [orig, resp] !in vert_table )
		vert_table[orig, resp] = set();

	add vert_table[orig, resp][id];

	local hcount = length(horiz_table[orig, id]);
	local vcount = length(vert_table[orig, resp]);

	if ( hcount in horiz_scan_thresholds && hcount != last_hthresh[orig] )
		{
		local horz_scan_msg =
			fmt("%s has triggered signature %s on %d hosts",
				orig, id, hcount);

		signature_file_write([$note=MultipleSigResponders,
			$src_addr=orig, $sig_id=id, $event_msg=msg,
			$host_count=hcount, $sub_msg=horz_scan_msg]);

		NOTICE([$note=MultipleSigResponders, $src=orig, $filename=id,
			$msg=msg, $n=hcount, $sub=horz_scan_msg]);

		last_hthresh[orig] = hcount;
		}

	if ( vcount in vert_scan_thresholds && vcount != last_vthresh[orig] )
		{
		local vert_scan_msg =
			fmt("%s has triggered %d different signatures on host %s",
				orig, vcount, resp);

		signature_file_write([$note=MultipleSignatures, $src_addr=orig,
			$dst_addr=resp, $sig_id=id, $sig_count=vcount,
			$event_msg= fmt("%s different signatures triggered",
					vcount),
			$sub_msg=vert_scan_msg]);

		NOTICE([$note=MultipleSignatures, $src=orig, $dst=resp,
			$filename=id,
			$msg=fmt("%s different signatures triggered", vcount),
			$n=vcount, $sub=vert_scan_msg]);

		last_vthresh[orig] = vcount;
		}
	}

# Returns true if the given signature has already been triggered for the given
# [orig, resp] pair.
function has_signature_matched(id: string, orig: addr, resp: addr): bool
	{
	return [orig, resp] in vert_table ? id in vert_table[orig, resp] : F;
	}
