##! Script level signature support.

module Signatures;

export {
	redef enum Notice::Type += {
		## Generic for alarm-worthy
		Sensitive_Signature,
		## Host has triggered many signatures on the same host.  The number of 
		## signatures is defined by the :bro:id:`vert_scan_thresholds` variable.
		Multiple_Signatures,
		## Host has triggered the same signature on multiple hosts as defined by the
		## :bro:id:`horiz_scan_thresholds` variable.
		Multiple_Sig_Responders,
		## The same signature has triggered multiple times for a host.  The number 
		## of times the signature has be trigger is defined by the 
		## :bro:id:`count_thresholds` variable.  To generate this notice, the
		## :bro:enum:`SIG_COUNT_PER_RESP` action must be set for the signature.
		Count_Signature,
		## Summarize the number of times a host triggered a signature.  The 
		## interval between summaries is defined by the :bro:id:`summary_interval` 
		## variable.
		Signature_Summary,
	};

	redef enum Log::ID += { SIGNATURES };

	## These are the default actions you can apply to signature matches.
	## All of them write the signature record to the logging stream unless
	## declared otherwise.
	type Action: enum {
		## Ignore this signature completely (even for scan detection).  Don't
		## write to the signatures logging stream.
		SIG_IGNORE,
		## Process through the various aggregate techniques, but don't report 
		## individually and don't write to the signatures logging stream.
		SIG_QUIET,
		## Generate a notice.
		SIG_LOG,
		## The same as :bro:enum:`SIG_FILE`, but ignore for aggregate/scan
		## processing.
		SIG_FILE_BUT_NO_SCAN,
		## Generate a notice and set it to be alarmed upon.
		SIG_ALARM,
		## Alarm once per originator.
		SIG_ALARM_PER_ORIG,
		## Alarm once and then never again.
		SIG_ALARM_ONCE,
		## Count signatures per responder host and alarm with the 
		## :bro:enum:`Count_Signature` notice if a threshold defined by
		## :bro:id:`count_thresholds` is reached.
		SIG_COUNT_PER_RESP,
		## Don't alarm, but generate per-orig summary.
		SIG_SUMMARY,
	};
	
	type Info: record {
		ts:         time         &log;
		src_addr:   addr         &log &optional;
		src_port:   port         &log &optional;
		dst_addr:   addr         &log &optional;
		dst_port:   port         &log &optional;
		## Notice associated with signature event
		note:       Notice::Type &log;
		sig_id:     string       &log &optional;
		event_msg:  string       &log &optional;
		## Extracted payload data or extra message.
		sub_msg:    string       &log &optional;
		## Number of sigs, usually from summary count.
		sig_count:  count        &log &optional;
		## Number of hosts, from a summary count.
		host_count: count        &log &optional;
	};
	
	## Actions for a signature.  
	const actions: table[string] of Action =  {
		["unspecified"] = SIG_IGNORE, # place-holder
	} &redef &default = SIG_ALARM;

	## Signature IDs that should always be ignored.
	const ignored_ids = /NO_DEFAULT_MATCHES/ &redef;
	
	## Alarm if, for a pair [orig, signature], the number of different 
	## responders has reached one of the thresholds.
	const horiz_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;

	## Alarm if, for a pair [orig, resp], the number of different signature 
	## matches has reached one of the thresholds.
	const vert_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;

	## Alarm if a :bro:enum:`SIG_COUNT_PER_RESP` signature is triggered as 
	## often as given by one of these thresholds.
	const count_thresholds = { 5, 10, 50, 100, 500, 1000, 10000, 1000000, } &redef;
	
	## The interval between when :bro:id:`Signature_Summary` notices are 
	## generated.
	const summary_interval = 1 day &redef;
	
	global log_signature: event(rec: Info);
}

global horiz_table: table[addr, string] of addr_set &read_expire = 1 hr;
global vert_table: table[addr, addr] of string_set &read_expire = 1 hr;
global last_hthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global last_vthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global count_per_resp: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global count_per_orig: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global did_sig_log: set[string] &read_expire = 1 hr;


event bro_init()
	{
	Log::create_stream(SIGNATURES, [$columns=Info, $ev=log_signature]);
	}
		
# Returns true if the given signature has already been triggered for the given
# [orig, resp] pair.
function has_signature_matched(id: string, orig: addr, resp: addr): bool
	{
	return [orig, resp] in vert_table ? id in vert_table[orig, resp] : F;
	}

event sig_summary(orig: addr, id: string, msg: string)
	{
	NOTICE([$note=Signature_Summary, $src=orig,
	        $filename=id, $msg=fmt("%s: %s", orig, msg),
	        $n=count_per_orig[orig,id] ]);
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	local sig_id = state$sig_id;
	local action = actions[sig_id];

	if ( action == SIG_IGNORE || ignored_ids in sig_id )
		return;

	# Trim the matched data down to something reasonable
	if ( byte_len(data) > 140 )
		data = fmt("%s...", sub_bytes(data, 0, 140));
		
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

	if ( action != SIG_QUIET && action != SIG_COUNT_PER_RESP )
		{
		local info: Info = [$ts=network_time(),
		                    $note=Sensitive_Signature,
		                    $src_addr=src_addr,
		                    $src_port=src_port,
		                    $dst_addr=dst_addr,
		                    $dst_port=dst_port,
		                    $event_msg=fmt("%s: %s", src_addr, msg),
		                    $sig_id=sig_id,
		                    $sub_msg=data];
		Log::write(SIGNATURES, info);
		}

	local notice = F;
	if ( action == SIG_ALARM )
		notice = T;
	
	if ( action == SIG_COUNT_PER_RESP )
		{
		local dst = state$conn$id$resp_h;
		if ( ++count_per_resp[dst,sig_id] in count_thresholds )
			{
			NOTICE([$note=Count_Signature, $conn=state$conn,
				   $msg=msg,
				   $filename=sig_id,
				   $n=count_per_resp[dst,sig_id],
				   $sub=fmt("%d matches of signature %s on host %s",
						count_per_resp[dst,sig_id],
						sig_id, dst)]);
			}
		}

	if ( (action == SIG_ALARM_PER_ORIG || action == SIG_SUMMARY) &&
	     ++count_per_orig[state$conn$id$orig_h, sig_id] == 1 )
		{
		if ( action == SIG_ALARM_PER_ORIG )
			notice = T;
		else
			schedule summary_interval {
				sig_summary(state$conn$id$orig_h, sig_id, msg)
			};
		}

	if ( action == SIG_ALARM_ONCE )
		{
		if ( [sig_id] !in did_sig_log )
			{
			notice = T;
			add did_sig_log[sig_id];
			}
		}

	if ( notice )
		NOTICE([$note=Sensitive_Signature,
		        $conn=state$conn, $src=src_addr,
		        $dst=dst_addr, $filename=sig_id, $msg=fmt("%s: %s", src_addr, msg),
		        $sub=data]);
	
	if ( action == SIG_FILE_BUT_NO_SCAN || action == SIG_SUMMARY )
		return;

	# Keep track of scans.
	local orig = state$conn$id$orig_h;
	local resp = state$conn$id$resp_h;

	if ( [orig, sig_id] !in horiz_table )
		horiz_table[orig, sig_id] = set();

	add horiz_table[orig, sig_id][resp];

	if ( [orig, resp] !in vert_table )
		vert_table[orig, resp] = set();

	add vert_table[orig, resp][sig_id];

	local hcount = length(horiz_table[orig, sig_id]);
	local vcount = length(vert_table[orig, resp]);

	if ( hcount in horiz_scan_thresholds && hcount != last_hthresh[orig] )
		{
		local horz_scan_msg =
			fmt("%s has triggered signature %s on %d hosts",
				orig, sig_id, hcount);

		Log::write(SIGNATURES, 
			[$note=Multiple_Sig_Responders,
		     $src_addr=orig, $sig_id=sig_id, $event_msg=msg,
		     $host_count=hcount, $sub_msg=horz_scan_msg]);

		NOTICE([$note=Multiple_Sig_Responders, $src=orig, $filename=sig_id,
			$msg=msg, $n=hcount, $sub=horz_scan_msg]);

		last_hthresh[orig] = hcount;
		}

	if ( vcount in vert_scan_thresholds && vcount != last_vthresh[orig] )
		{
		local vert_scan_msg =
			fmt("%s has triggered %d different signatures on host %s",
				orig, vcount, resp);

		Log::write(SIGNATURES, 
			[$ts=network_time(),
			 $note=Multiple_Signatures, 
			 $src_addr=orig,
			 $dst_addr=resp, $sig_id=sig_id, $sig_count=vcount,
			 $event_msg=fmt("%s different signatures triggered", vcount),
			 $sub_msg=vert_scan_msg]);

		NOTICE([$note=Multiple_Signatures, $src=orig, $dst=resp,
			$filename=sig_id,
			$msg=fmt("%s different signatures triggered", vcount),
			$n=vcount, $sub=vert_scan_msg]);

		last_vthresh[orig] = vcount;
		}
	}

