##! This is the notice framework which enables Bro to "notice" things which
##! are odd or potentially bad.  Decisions of the meaning of various notices
##! need to be done per site because Bro does not ship with assumptions about
##! what is bad activity for sites.  More extensive documetation about using
##! the notice framework can be found in the documentation section of the
##! http://www.bro-ids.org/ website.

@load conn/base

module Notice;

# This couldn't be named NOTICE because that id is already used by the
# global function NOTICE().
redef enum Log::ID += { NOTICE_LOG };

export {
	## Scripts creating new notices need to redef this enum to add their own 
	## specific notice types which would then get used when they call the
	## :bro:id:`NOTICE` function.  The convention is to give a general category
	## along with the specific notice separating words with underscores and using
	## leading capitals on each word except for abbreviations which are kept in
	## all capitals.  For example, SSH_Login is for heuristically guessed 
	## successful SSH logins.
	type Type: enum {
		## Notice reporting a count of how often a notice occurred.
		Notice_Tally,
	};
	
	## These are values representing actions that can be taken with notices.
	type Action: enum {
		## The default unknown action.
		ACTION_UNKNOWN,
		## Indicates that no action should be taken with the notice.
		ACTION_IGNORE, 
		## Indicates that the notice should always be turned into an alarm.
		ACTION_ALARM_ALWAYS,
		## Indicates that the notice should be sent to the contact email.
		ACTION_EMAIL, 
		## Indicates that the notice should be sent to the notice file.
		ACTION_FILE, 
		## Indicates that the notice should be sent to the configured pager 
		## email address.
		ACTION_PAGE,
	};
	
	type Info: record {
		ts:             time    &log &optional;
		uid:            string  &log &optional;
		id:             conn_id &log &optional;
		
		## This is the relevant host for this notice.  It could be set because
		## either:
		##
		## 1. There is no connection associated with this notice.
		## 2. There is some underlying semantic of the notice where either
		##    orig_h or resp_h is the relevant host in the associated
		##    connection.  For example, if a host is detected scanning, the
		##    particular connection taking place when the notice is generated
		##    is irrelevant and only the host detected scanning is relevant.
		relevant_host:  addr    &log &optional;
		
		## The :bro:enum:`Notice::Type` of the notice.
		note:           Type    &log;
		msg:            string  &log &optional; ##< The human readable message for the notice.
		sub:            string  &log &optional; ##< Sub-message.

		src:            addr    &log &optional; ##< Source address, if we don't have a connection.
		dst:            addr    &log &optional; ##< Destination address.
		p:              port    &log &optional; ##< Associated port, if we don't have a connection.
		n:              count   &log &optional; ##< Associated count, or perhaps a status code.

		conn:           connection &optional;   ##< Connection associated with the notice.
		iconn:          icmp_conn  &optional;   ##< Associated ICMP "connection".

		## The action assigned to this notice after being processed by the 
		## various action assigning methods.
		action:         Notice::Action &log &default=ACTION_UNKNOWN;
		## Peer that raised this notice.
		src_peer:       event_peer     &log &optional;
		## Uniquely identifying tag associated with this notice.
		tag:            string         &log &optional;

		## This value controls and indicates if alarms should be bumped up
		## to alarms independent of all other notice actions and filters.
		## If false, don't alarm independent of the determined notice action.
		## If true, alarm dependening on notice action.
		do_alarm: bool &log &default=T;
	};

	type PolicyItem: record {
		result: Notice::Action &default=ACTION_FILE;
		pred: function(n: Notice::Info): bool;
		priority: count &default=1;
	};
	
	# This is the :bro:id:`Notice::policy` where the local notice conversion 
	# policy is set.
	const policy: set[Notice::PolicyItem] = {
		[$pred(n: Notice::Info) = { return T; },
		 $result = ACTION_ALARM_ALWAYS,
		 $priority = 0],
	} &redef;
	
	## Local system mail program.
	const mail_script    = "/bin/mail" &redef;
	## Email address to send notices with the :bro:enum:`ACTION_EMAIL` action.
	const mail_dest      = ""          &redef;
	## Email address to send notices with the :bro:enum:`ACTION_PAGE` action.
	const mail_page_dest = ""          &redef;
	
	## Do not generate notice_action events for these notice types.
	const suppress_notice_actions: set[Type] &redef; 
	
	## Hack to suppress duplicate notice_actions for remote notices.  Normally
	## this setting should be left alone.
	global suppress_notice_action = F;
		
	# Table that maps notices into a function that should be called
	# to determine the action.
	const action_filters:
		table[Notice::Type] of
			function(n: Notice::Info, a: Notice::Action): Notice::Action &redef;
	
	## This is a set of functions that provide a synchronous way for scripts 
	## extending the notice framework to run before the normal event based
	## notice pathway that most of the notice framework takes.  This is helpful
	## in cases where an action against a notice needs to happen immediately
	## and can't wait the short time for the event to bubble up to the top of
	## the event queue.  An example is the IP address dropping script that 
	## can block IP addresses that have notices generated because it 
	## needs to operate closer to real time than the event queue allows it to.
	## Normally the event based extension model using the 
	## :bro:id:`Notice::notice` event will work fine if there aren't harder
	## real time constraints.
	const notice_functions: set[function(n: Notice::Info)] = set() &redef;
	
	# This should have a high probability of being unique without
	# generating overly long tags.  This is redef'able in case you need
	# determinism in tags (such as for regression testing).
	const notice_tag_prefix =
		fmt("%x-%x-",
		    double_to_count(time_to_double(current_time())) % 255,
		    getpid()) &redef;

	# Likewise redef'able for regression testing.
	const new_notice_tag = function(): string { return ""; } &redef;

	## This event is generated to send email.  This script includes a handler
	## for this event which sends email already.
	global email_notice_to: event(n: Info, dest: string) &redef;
	
	## This is the event that is called as the entry point to the 
	## notice framework by the global :bro:id:`NOTICE` function.  By the time 
	## this event is generated, default values have already been filled out in
	## the :bro:type:`Notice::Info` record and synchronous functions in the 
	## :bro:id:`Notice:notice_functions` have already been called.
	global notice: event(n: Info);
	
	## This event is useful for processing notices after the notice filters
	## have been applied and yielded a Notice::Action.
	global notice_action: event(n: Notice::Info, action: Notice::Action);
	
	## Similar to :bro:id:`Notice::notice_action` but only generated if the
	## notice also triggers an alarm.
	global notice_alarm: event(n: Notice::Info, action: Notice::Action);
	
	## This is an internally used function.  Please ignore it, it's only used
	## for filling out missing details of :bro:type:`Notice:Info` records
	## before the synchronous and asynchronous event pathways have begun.
	global fill_in_missing_details: function(n: Notice::Info);
	
	## This event can be handled to access the :bro:type:`Info`
	## record as it is sent on to the logging framework.
	global log_notice: event(rec: Info);
}

redef record Conn::Info += {
	notice_tags: set[string] &log &optional;
};

# Each notice has a unique ID associated with it.
global notice_id = 0;
redef new_notice_tag = function(): string
		{ return fmt("%s%x", notice_tag_prefix, ++notice_id); };

event bro_init()
	{
	Log::create_stream(NOTICE_LOG, [$columns=Info, $ev=log_notice]);
	}

# TODO: fix this.
#function notice_tags(n: Notice::Info) : table[string] of string
#	{
#	local tgs: table[string] of string = table();
#	if ( is_remote_event() )
#		{
#		if ( n$src_peer$descr != "" )
#			tgs["es"] = n$src_peer$descr;
#		else
#			tgs["es"] = fmt("%s/%s", n$src_peer$host, n$src_peer$p);
#		}
#	else
#		{
#		tgs["es"] = peer_description;
#		}
#	return tgs;
#	}

event email_notice_to(n: Notice::Info, dest: string)
	{
	if ( reading_traces() || dest == "" )
		return;

	# The contortions here ensure that the arguments to the mail
	# script will not be confused.  Re-evaluate if 'system' is reworked.
	local mail_cmd =
		fmt("echo \"%s\" | %s -s \"[Bro Alarm] %s\" %s",
			str_shell_escape(n$msg), mail_script, n$note, dest);

	system(mail_cmd);
	}

function email_notice(n: Notice::Info, action: Notice::Action)
	{
	# Choose destination address based on action type.
	local dest = (action == ACTION_EMAIL) ? mail_dest : mail_page_dest;
	event email_notice_to(n, dest);
	}

# Executes a script with all of the notice fields put into the
# new process' environment as "BRO_ARG_<field>" variables.
function execute_with_notice(cmd: string, n: Notice::Info)
	{
	# TODO: fix system calls
	#local tgs = tags(n);
	#system_env(cmd, tags);
	}
	
# This is run synchronously as a function before all of the other 
# notice related functions and events.  It also modifies the 
# :bro:type:`Notice::Info` record in place.
function fill_in_missing_details(n: Notice::Info)
	{
	# Fill in some defaults.
	n$ts = network_time();

	if ( n?$conn )
		{
		n$uid = n$conn$uid;
		if ( ! n?$id )
			n$id = n$conn$id;
		}

	if ( ! n?$src && n?$id )
		n$src = n$id$orig_h;
	if ( ! n?$dst && n?$id )
		n$dst = n$id$resp_h;

	if ( ! n?$p && n?$id )
		n$p = n$id$resp_p;

	if ( ! n?$src && n?$iconn )
		n$src = n$iconn$orig_h;
	if ( ! n?$dst && n?$iconn )
		n$dst = n$iconn$resp_h;

	# Auto-set $relevant_host to $src if $src was given as the "relevant host"
	# This keeps with existing usage for the $src field while applying the 
	# new relevant host semantics to it.
	if ( ! n?$relevant_host && n?$src && ! n?$dst )

	if ( ! n?$src_peer )
		n$src_peer = get_event_peer();

	n$tag = new_notice_tag();

	# Add the tag to the connection's notice_tags if there is a connection.
	if ( n?$conn && n$conn?$conn )
		{
		if ( ! n$conn$conn?$notice_tags )
			n$conn$conn$notice_tags = set();
		add n$conn$conn$notice_tags[n$tag];
		}
		
	local action = match n using policy;
	if ( action != ACTION_IGNORE && 
	     action != ACTION_FILE &&
	     n$note in action_filters )
		action = action_filters[n$note](n, action);

	n$action = action;
	}
	
event notice(n: Notice::Info) &priority=-5
	{
	if ( n$action == ACTION_EMAIL || n$action == ACTION_PAGE )
		email_notice(n, n$action);

	if ( n$action != ACTION_IGNORE )
		{
		Log::write(NOTICE_LOG, n);

		if ( n$action != ACTION_FILE && n$do_alarm )
			{
			# TODO: alarm may turn into a filter.
			#alarm n;
			event notice_alarm(n, n$action);
			}
		}

@ifdef ( IDMEF_support )
	if ( n?$id )
		generate_idmef(n$id$orig_h, n$id$orig_p, n$id$resp_h, n$id$resp_p);
@endif

	if ( ! suppress_notice_action && n$note !in suppress_notice_actions )
		event notice_action(n, n$action);
	}

module GLOBAL;

## This is the wrapper in the global namespace for the :bro:id:`Notice::notice`
## event.
function NOTICE(n: Notice::Info)
	{
	Notice::fill_in_missing_details(n);
	for ( func in Notice::notice_functions )
		{
		func(n);
		}
	event Notice::notice(n);
	}
