# $Id:$
#
# drop.bro implements a drop/restore policy termed "catch-and-release"
# whereby the first time an address is dropped, it is restored a while after
# the last connection attempt seen.  If a connection attempt is subsequently
# seen, however, then the system is blocked again, and for a longer time.
#
# This policy has significant benefits when using Bro to update router
# ACLs for which:
#     - The router has a limited number of ACLs slots.
#     - You care about possible reuse of IP addresses by now-benign hosts,
#	so don't want blocks to last forever.
#
# Original code by Jim Mellander, LBNL.
# Updated by Brian Tierney, LBNL and by Robin Sommer, ICSI.

@load site

module Drop;

export {
	redef enum Notice += {
		# Connectivity with given address has been dropped.
		AddressDropped,

		# A request to drop connectivity has been ignored.
		AddressDropIgnored,

		# Connectivity with given address has been restored.
		AddressRestored,

		AddressAlreadyDropped,	# host is already dropped

		# Previously dropped host connects again.
		AddressSeenAgain,

		# Previous offenders re-dropped or re-restored.
		RepeatAddressDropped,
		RepeatAddressRestored,
	};

	# True if we have the capability to drop hosts at all.
	const can_drop_connectivity = F &redef;

	# True if we never want to drop local addresses.
	const dont_drop_locals = T &redef;

	# True if we should use the catch-and-release scheme.  If not then
	# we simply drop addresses via the drop_connectivity_script and
	# never restore them (they must be restored out-of-band).
	const use_catch_release = F &redef;

	# Catch-and-release parameters.

	# Interval to wait for release following inactivity after
	# first offense.
	global drop_time = 5 min &redef;

	# For repeat offenders: if the total time a host has already been
	# dropped reaches persistent_offender_time, we drop the host for
	# long_drop_time.  Setting persistent_offender_time to zero disables
	# this functionality.
	const persistent_offender_time = 2 hr &redef;
	global long_drop_time = 12 hr &redef;

	# Scripts to perform the actual dropping/restore. They get the
	# IP address as their first argument.
	const drop_connectivity_script = "drop-connectivity" &redef;
	const restore_connectivity_script = "restore-connectivity" &redef;

	const root_servers = {
		a.root-servers.net, b.root-servers.net, c.root-servers.net,
		d.root-servers.net, e.root-servers.net, f.root-servers.net,
		g.root-servers.net, h.root-servers.net, i.root-servers.net,
		j.root-servers.net, k.root-servers.net, l.root-servers.net,
		m.root-servers.net,
	} &redef;

	const gtld_servers = {
		a.gtld-servers.net, b.gtld-servers.net, c.gtld-servers.net,
		d.gtld-servers.net, e.gtld-servers.net, f.gtld-servers.net,
		g.gtld-servers.net, h.gtld-servers.net, i.gtld-servers.net,
		j.gtld-servers.net, k.gtld-servers.net, l.gtld-servers.net,
		m.gtld-servers.net,
	} &redef;

	const never_shut_down = {
		root_servers, gtld_servers,
	} &redef;

	const never_drop_nets: set[subnet] &redef;

	# Drop the connectivity for the address. "msg" gives a reason.
	# It returns a copy of the NOTICE generated for the drop, which
	# gives more information about the kind of dropping performed.
	# If the notice type is NoticeNone, the drop was not successful
	# (e.g., because this Bro instance is not configured to do drops.)
	global drop_address: function(a: addr, msg: string) : notice_info;

	# The following events are used to communicate information about the
	# drops, in particular for C&R in the cluster setting.

	# Address has been dropped.
	global address_dropped: event(a: addr);

	# Raised when an IP is restored.
	global address_restored: event(a: addr);

	# Raised when an that was dropped in the past is no
	# longer monitored specifically for new connections.
	global address_cleared: event(a: addr);

	const debugging = F &redef;
	global debug_log: function(msg: string);
}

type drop_rec: record {
	tot_drop_count: count &default=0;
	tot_restore_count: count &default=0;
	actual_restore_count: count &default=0;
	tot_drop_time: interval &default=0secs;
	last_timeout: interval &default=0secs;
};

global clear_host: function(t: table[addr] of drop_rec, a: addr): interval;

global drop_info: table[addr] of drop_rec
	&read_expire = 1 days &expire_func=clear_host &persistent;

global last_notice: notice_info;

function do_notice(n: notice_info)
	{
	last_notice = n;
	NOTICE(n);
	}

function dont_drop(a: addr) : bool
	{
	return ! can_drop_connectivity || a in never_shut_down ||
	       a in never_drop_nets || (dont_drop_locals && is_local_addr(a));
	}

function is_dropped(a: addr) : bool
	{
	if ( a !in drop_info )
		return F;

	local di = drop_info[a];

	if ( di$tot_drop_count < di$tot_restore_count )
		{ # This shouldn't happen.
		# FIXME: We need an assert().
		print "run-time error: more restores than drops!";
		return F;
		}

	return di$tot_drop_count > di$tot_restore_count;
	}

global debug_log_file: file;

function debug_log(msg: string)
	{
	if ( ! debugging )
		return;

	print debug_log_file,
		fmt("%.6f [%s] %s", network_time(), peer_description, msg);
	}

event bro_init()
	{
	if ( debugging )
		{
		debug_log_file =
			open_log_file(fmt("drop-debug.%s", peer_description));
		set_buf(debug_log_file, F);
		}
	}

function do_direct_drop(a: addr, msg: string)
	{
	if ( msg != "" )
		msg = fmt(" (%s)", msg);

	if ( a !in drop_info )
		{
		local tmp: drop_rec;
		drop_info[a] = tmp;
		}

	local di = drop_info[a];

	if ( is_dropped(a) )
		# Already dropped. Nothing to do.
		do_notice([$note=Drop::AddressAlreadyDropped, $src=a,
				$msg=fmt("%s%s", a, msg)]);
	else
		{
		system(fmt("%s %s", Drop::drop_connectivity_script, a));

		debug_log(fmt("sending drop for %s", a));
		event Drop::address_dropped(a);

		if ( di$tot_drop_count == 0 )
			do_notice([$note=Drop::AddressDropped, $src=a,
					$msg=fmt("%s%s", a, msg)]);
		else
			{
			local s = fmt("(%d times)", di$tot_drop_count + 1);
			do_notice([$note=Drop::RepeatAddressDropped,
				$src=a, $n=di$tot_drop_count+1,
				$msg=fmt("%s%s %s", a, msg, s), $sub=s]);
			}
		}

	++di$tot_drop_count;
	debug_log(fmt("dropped %s: tot_drop_count=%d tot_restore_count=%d",
			a, di$tot_drop_count, di$tot_restore_count));
	}

# Restore a previously dropped address.
global do_restore: function(a: addr, force: bool);

event restore_dropped_address(a: addr)
	{
	do_restore(a, F);
	}

function do_catch_release_drop(a: addr, msg: string)
	{
	do_direct_drop(a, msg);

	local di = drop_info[a];

	local t = (persistent_offender_time != 0 sec &&
		   di$tot_drop_time >= persistent_offender_time) ?
			long_drop_time : drop_time;

	di$tot_drop_time += t;
	di$last_timeout = t;

	schedule t { restore_dropped_address(a) };
	}

function do_restore(a: addr, force: bool)
	{
	if ( a !in drop_info )
		return;

	local di = drop_info[a];
	++drop_info[a]$tot_restore_count;
	debug_log(fmt("restored %s: tot_drop_count=%d tot_restore_count=%d force=%s", a, drop_info[a]$tot_drop_count, drop_info[a]$tot_restore_count, force));

	if ( di$tot_drop_count == di$tot_restore_count || force )
		{
		++di$actual_restore_count;
		system(fmt("%s %s", Drop::restore_connectivity_script, a));

		debug_log(fmt("sending restored for %s", a));
		event Drop::address_restored(a);

		local t = di$last_timeout;

		if ( di$actual_restore_count == 1 )
			{
			local s1 = fmt("(timeout %.1f)", t);
			do_notice([$note=Drop::AddressRestored, $src=a,
				   $msg=fmt("%s %s", a, s1), $sub=s1]);
			}

		else
			{
			local s2 = fmt("(%d times, timeout %.1f)",
					di$actual_restore_count, t);
			do_notice([$note=Drop::RepeatAddressRestored, $src=a,
				   $n=di$tot_restore_count,
				   $msg=fmt("%s %s", a, s2), $sub=s2]);
			}
		}
	}

function clear_host(t: table[addr] of drop_rec, a: addr): interval
	{
	if ( is_dropped(a) )
		# Restore address.
		do_restore(a, T);

	debug_log(fmt("sending cleared for %s", a));
	event Drop::address_cleared(a);

	return 0 secs;
	}

# Returns true if drop was successful (or IP was already dropped).
function drop_address(a: addr, msg: string) : notice_info
	{
	debug_log(fmt("drop_address(%s, %s)", a, msg));

	last_notice = [$note=NoticeNone];

	if ( dont_drop(a) )
		do_notice([$note=AddressDropIgnored, $src=a,
			$msg=fmt("ignoring request to drop %s (%s)", a, msg)]);
	else if ( use_catch_release )
		do_catch_release_drop(a, msg);
	else
		do_direct_drop(a, msg);

	if ( last_notice$note == NoticeNone )
		print "run-time error: drop_address did not raise a NOTICE";

	return last_notice;
	}

event new_connection(c: connection)
	{
	if ( ! can_drop_connectivity )
		return;

	# With Catch & Release, 1 connection from a previously dropped system
	# triggers an immediate redrop.
	if ( ! use_catch_release )
		return;

	local a = c$id$orig_h;

	if ( a !in drop_info )
		# Never dropped.
		return;

	local di = drop_info[a];
	if ( is_dropped(a) )
		# Still dropped.
		return;

	NOTICE([$note=AddressSeenAgain, $src=a,
		$msg=fmt("%s seen again after release", a)]);
	}
