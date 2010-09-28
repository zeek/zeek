# $Id: time-machine.bro,v 1.1.2.8 2006/01/06 01:51:37 sommer Exp $
#
# Low-level time-machine interface.

@load notice

module TimeMachine;

export {
	# Request to send us a connection.  Automatically subscribes
	# and suspends cut-off.
	#
	#   start : time where to start searching (0 for as early as possible).
	#   in_mem: only scan TM's memory-buffer but not any on-disk data.
	#   descr: description to be written to log file to identify the query
	#
	# Returns tag of this query.
	global request_connection:
		function(c: connection, in_mem: bool, descr: string) : string;

	# id$orig_p = 0/tcp acts as wildcard.
	global request_connection_id:
		function(id: conn_id, start: time, in_mem: bool, descr: string)
		: string;

	# Request to save connection to file in TM host.  Automatically
	# suspends cut-off.
	#
	#   filename: destination file on TM host.
	#   start   : time where to start searching (0 = as early as possible).
	#   in_mem  : only scan TM's memory-buffer, but not any on-disk data.
	global capture_connection:
		function(filename: string, c: connection, in_mem: bool,
				descr: string);

	# id$orig_p = 0/tcp acts as wildcard.
	global capture_connection_id:
		function(filename: string, id: conn_id, start: time,
				in_mem: bool, descr: string);

	# Request to send everything involving a certain host to us.
	# Always searches mem and disk buffers.
	#
	#   host : address of host
	#   start: time where to start searching (0 for as early as possible).
	#
	# Returns tag of this query.
	global request_addr: function(host: addr, start: time,
				in_mem: bool, descr: string) : string;

	# Don't issue duplicate queries.  Should be on for normal use;
	# only need to turn off for benchmarking.
	global filter_duplicates = T &redef;

	# Automatically issue suspend_cutoff as specified above.
	# Should be on for normal use; off only used for benchmarking.
	global auto_suspend_cutoff = T &redef;

	# Automatically subscribe as specified above.
	# Should be on for normal use; off only used for benchmarking.
	global auto_subscribe = F &redef;

	# Automatically set start time for query.
	# Should be on for normal use; off only used for benchmarking.
	global auto_set_start = T &redef;

	# Request to save everything involving a certain host.
	# Always searches mem and disk buffers.
	#
	#   filename: destination file on TM host.
	#   host : address of host
	#   start: time where to start searching (0 for as early as possible).
	#
	global capture_addr: function(filename: string, host: addr,
					start: time, in_mem: bool,
					descr: string);

	# Prevent the TM from cutting the connection off.
	global suspend_cut_off: function(c: connection, descr: string);

	# id$orig_p = 0/tcp acts as wildcard.
	global suspend_cut_off_id: function(id: conn_id, descr: string);

	type Direction: enum {
		ORIG,	# connections originating from host
		RESP,	# connections responded to by host
		BOTH	# independent of direction
	};

	# Change the TM class for given IP.
	global set_class: function(host: addr, class: string, dir: Direction,
					descr: string);

	# Revoke class assignment for IP.
	global unset_class: function(host: addr, descr: string);

	# ID of this Bro instance for TM queries.  Automatically set.
	global feed_id = "";
}

global tag = 0;

global cmds: table[string] of string &read_expire = 1 day;

global command: event(cmd: string);
global descrs: table[string] of string;

global profile: file;
global logfile = open_log_file("tm");

function id2str(id: conn_id, include_index: bool) : string
	{
	local index = "";
	if ( include_index )
		index = id$orig_p != 0/tcp ? "connection4 " : "connection3 ";

	if ( id$orig_p != 0/tcp)
		return fmt("%s\"%s %s:%d %s:%d\"", index,
			get_port_transport_proto(id$resp_p),
			id$orig_h, id$orig_p,
			id$resp_h, id$resp_p);
	else
		return fmt("%s\"%s %s %s:%d\"", index,
			get_port_transport_proto(id$resp_p),
			id$orig_h,
			id$resp_h, id$resp_p);
	}

function issue_query(result: string, add_tag: bool, cmd: string,
			start: time, in_mem: bool, sub: bool, descr: string) : string
	{
	local key = fmt("%s %s", result, cmd);
	local qtag = "";

	if ( key in cmds && filter_duplicates )
		return cmds[key];

	if ( add_tag )
		{
		qtag = fmt("t%x", ++tag);
		result = fmt("%s tag %s", result, qtag);
		}

	local range = "";

	if ( time_to_double(start) > 0.0 && auto_set_start )
		{ # We subtract a few seconds to allow for clock skew.
		start = start -  2 secs;
		range += fmt("start %.6f end 9876543210 ", start);
		}

	if ( in_mem )
		range += "mem_only ";

	if ( sub )
		range += "subscribe ";

	local c = fmt("query %s %s %s", result, cmd, range);
	descrs[c] = descr;

	if ( time_machine_profiling )
		print profile, fmt("%.6f %s %s", current_time(),
					(qtag != "" ? qtag : "-"), c);

	event TimeMachine::command(c);

	cmds[key] = qtag;

	return qtag;
	}

function issue_command(cmd: string, descr: string)
	{
	if ( cmd in cmds && filter_duplicates )
		return;

	descrs[cmd] = descr;
	event TimeMachine::command(cmd);

	cmds[cmd] = "";
	}

function request_connection(c: connection, in_mem: bool, descr: string) : string
	{
	return request_connection_id(c$id, c$start_time, in_mem, descr);
	}

function request_connection_id(id: conn_id, start: time, in_mem: bool,
				descr: string) : string
	{
	if ( auto_suspend_cutoff )
		suspend_cut_off_id(id, descr);
	return issue_query(fmt("feed %s", feed_id), T,
		fmt("index %s", id2str(id, T)), start, in_mem,
			auto_subscribe, descr);
	}

function capture_connection(filename: string, c: connection,
				in_mem: bool, descr: string)
	{
	capture_connection_id(filename, c$id, c$start_time, in_mem, descr);
	}

function capture_connection_id(filename: string, id: conn_id, start: time,
				in_mem: bool, descr: string)
	{
	if ( auto_suspend_cutoff )
		suspend_cut_off_id(id, descr);

	issue_query(fmt("to_file \"%s\"", filename), F,
			fmt("index %s", id2str(id, T)),
			start, in_mem, auto_subscribe, descr);
	}

function request_addr(host: addr, start: time, in_mem: bool, descr: string)
: string
	{
	return issue_query(fmt("feed %s", feed_id), T,
			fmt("index ip \"%s\"", host), start, in_mem, F, descr);
	}

function capture_addr(filename: string, host: addr, start: time,
			in_mem: bool, descr: string)
	{
	issue_query(fmt("to_file \"%s\"", filename), F,
			fmt("index ip \"%s\"", host), start, in_mem, F, descr);
	}

function suspend_cut_off(c: connection, descr: string)
	{
	suspend_cut_off_id(c$id, descr);
	}

function suspend_cut_off_id(id: conn_id, descr: string)
	{
	issue_command(fmt("suspend_cutoff %s", id2str(id, F)), descr);
	}

function set_class(host: addr, class: string, dir: Direction, descr: string)
	{
	local d = "";

	if ( dir == ORIG )
		d = " orig";
	else if ( dir == RESP )
		d = " resp";

	issue_command(fmt("set_dyn_class %s %s%s", host, class, d), descr);
	}

function unset_class(host: addr, descr: string)
	{
	issue_command(fmt("unset_dyn_class %s", host), descr);
	}

event command(cmd: string)
	{
	# We might not know the command if we're just relaying the event
	# from external.
	if ( cmd in descrs )
		{
		local descr = descrs[cmd];
		delete descrs[cmd];

		print logfile, fmt("%.6f %.6f [%s] %s", network_time(), current_time(), descr, cmd);
		}
	}

event bro_init()
	{
	set_buf(logfile, F);

	# Create a feed ID that's unique across restarts w/ high probability.
	feed_id = fmt("%s-%d-%d", gethostname(), getpid(), rand(100));

	if ( time_machine_profiling )
		profile = open_log_file("tm-prof.queries");
	}
