# $Id: adu.bro 5152 2007-12-04 21:48:56Z vern $

@load conn-id

module adu;

# This script parses application-layer data (ADU) units, or "messages",
# out of the packet streams.  Since the analysis is generic, we define
# an ADU simply as all application-layer data in a 5-tuple flow going
# in one direction without any data going the other way.  Once we see
# data in the other direction, we finish the current ADU and start
# a new one (going the other way).  While this approach is only
# approximate, it can work well for both UDP and TCP.
#
# The script reports ADUs as strings, up to a configurable maximum size, and
# up to a configurable depth into the flow.
#
# Generated events:
#
# - adu_tx(c: connection, a: adu_state) reports an ADU seen from
#   c's originator to its responder.
#
# - adu_rx(c: connection, a: adu_state) reports an ADU seen from
#   c's responder to the originator.
#
# - adu_done(c: connection) indicates that no more ADUs will be seen
#   on connection c. This is useful to know in case your statekeeping
#   relies on event connection_state_remove(), which is also used by
#   adu.bro.
#

# --- Input configuration -- which ports to look at --------------------

# Right now: everything!
#
redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;
redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;

# --- Debugging -- should really be a separate policy ------------------

# Comment out to disable debugging output:
#global adu_debug = T;

# Uncomment to enable tests:
#global adu_test = T;

@ifdef (adu_debug)
function DBG(msg: string) { print fmt("DBG[adu.bro]: %s", msg); }
@else
function DBG(msg: string) { }
@endif

export {

# --- Constants --------------------------------------------------------

	# The maximum depth in bytes up to which we follow a flow.
	# This is counting bytes seen in both directions.
	const adu_conn_max_depth    = 100000 &redef;

	# The maximum message depth that we report.
	const adu_max_depth         = 3 &redef;

	# The maximum message size in bytes that we report.
	const adu_max_size          = 1000 &redef;

	# Whether ADUs are reported beyond content gaps.
	const adu_gaps_ok           = F &redef;

# --- Types ------------------------------------------------------------

	# adu_state records contain the latest ADU and aditional flags to help
	# the user identify the direction of the message, its depth in the flow,
	# etc.
	type adu_state: record {
		adu: string     &default = "";	# the current ADU

		# Message counter (>= 1), orig->resp and resp->orig.
		depth_tx: count &default = 1;
		depth_rx: count &default = 1;

		# TCP: seqno tracking to recognize gaps.
		seen_tx: count  &default = 0;
		seen_rx: count  &default = 0;

		size: count     &default = 0;	# total connection size in bytes
		is_orig: bool   &default = F;	# whether ADU is orig->resp
		ignore: bool	&default = F;	# ignore future activity on conn
	};

	# Tell the ADU policy that you do not wish to receive further
	# adu_tx/adu_rx events for a given connection. Other policies
	# may continue to process the connection.
	#
	global adu_skip_further_processing: function(cid: conn_id);
}


# --- Globals ----------------------------------------------------------

# A global table that tracks each flow's messages.
global adu_conns: table[conn_id] of adu_state;

# Testing invokes the following events.
global adu_tx: event(c: connection, astate: adu_state);
global adu_rx: event(c: connection, astate: adu_state);
global adu_done: event(c: connection);

# --- Functions --------------------------------------------------------

function adu_skip_further_processing(cid: conn_id)
	{
	if ( cid !in adu_conns )
		return;

	adu_conns[cid]$ignore = T;
	}

function flow_contents(c: connection, is_orig: bool, seq: count, contents: string)
	{
	local astate: adu_state;

	DBG(fmt("contents %s, %s: %s", id_string(c$id), is_orig, contents));

	# Ensure we track the given connection.
	if ( c$id !in adu_conns )
		adu_conns[c$id] = astate;
	else
		astate = adu_conns[c$id];

	# Forget it if we've been asked to ignore.
	#
	if ( astate$ignore == T )
		return;

	# Don't report if flow is too big.
	#
	if ( astate$size >= adu_conn_max_depth )
		return;

	# If we have an assembled message, we may now have something
	# to report.
	if ( |astate$adu| > 0 )
		{
		# If application-layer data flow is switching
		# from resp->orig to orig->resp, report the assembled
		# message as a received ADU.
		if ( is_orig && ! astate$is_orig )
			{
			event adu_rx(c, copy(astate));
			astate$adu = "";

			if ( ++astate$depth_rx > adu_max_depth )
				adu_skip_further_processing(c$id);
			}

		# If application-layer data flow is switching
		# from orig->resp to resp->orig, report the assembled
		# message as a transmitted ADU.
		#
		if ( !is_orig && astate$is_orig )
			{
			event adu_tx(c, copy(astate));
			astate$adu = "";

			if ( ++astate$depth_tx > adu_max_depth )
				adu_skip_further_processing(c$id);
			}
		}

	# Check for content gaps. If we identify one, only continue
	# if user allowed it.
	#
	if ( !adu_gaps_ok && seq > 0 )
		{
		if ( is_orig )
			{
			if ( seq > astate$seen_tx + 1 )
				return;
			else
				astate$seen_tx += |contents|;
			}
		else
			{
			if ( seq > astate$seen_rx + 1 )
				return;
			else
				astate$seen_rx += |contents|;
			}
		}

	# Append the contents to the end of the currently
	# assembled message, if the message hasn't already
	# reached the maximum size.
	#
	if ( |astate$adu| < adu_max_size )
		{
		astate$adu += contents;

		# As a precaution, clip the string to the maximum
		# size. A long content string with astate$adu just
		# below its maximum allowed size could exceed that
		# limit by a lot.
		### str_clip(astate$adu, adu_max_size);
		}


	# Note that this counter is bumped up even if we have
	# exceeded the maximum size of an individual message.
	#
	astate$size += |contents|;

	astate$is_orig = is_orig;
	}

# --- Event Handlers ---------------------------------------------------

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
	{
	flow_contents(c, is_orig, seq, contents);
	}

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
	flow_contents(u, is_orig, 0, contents);
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in adu_conns )
		return;

	local astate = adu_conns[c$id];

	# Forget it if we've been asked to ignore.
	#
	if ( astate$ignore == T )
		return;

	# Report the remaining data now, if any.
	#
	if ( |astate$adu| > 0 ) {
		if ( astate$is_orig )
			{
			if ( astate$depth_tx <= adu_max_depth )
				event adu_tx(c, copy(astate));
			}
		else
			{
			if ( astate$depth_rx <= adu_max_depth )
				event adu_rx(c, copy(astate));
			}
	}

	delete adu_conns[c$id];
	event adu_done(c);
}


# --- Tests ------------------------------------------------------------

@ifdef (adu_test)

event adu_tx(c: connection, astate: adu_state)
	{
	print fmt("%s ---- %s, %d -> ----", network_time(), id_string(c$id), astate$depth_tx);
#	print astate$adu;
	}

event adu_rx(c: connection, astate: adu_state)
	{
	print fmt("%s ---- %s, %d <- ----", network_time(), id_string(c$id), astate$depth_rx);
#	print astate$adu;
	}

@endif
