##! This is the notice framework which enables Bro to "notice" things which
##! are odd or potentially bad.  Decisions of the meaning of various notices
##! need to be done per site because Bro does not ship with assumptions about
##! what is bad activity for sites.  More extensive documetation about using
##! the notice framework can be found in the documentation section of the
##! http://www.bro-ids.org/ website.

@load conn/base

module Notice;

export {
	redef enum Log::ID += { 
		## This is the primary logging stream for notices.  It must always be
		## referenced with the module name included because the name is 
		## also used by the global function :bro:id:`NOTICE`.
		NOTICE, 
		## This is the notice policy auditing log.  It records what the current
		## notice policy is at Bro init time..
		NOTICE_POLICY,
	};

	## Scripts creating new notices need to redef this enum to add their own 
	## specific notice types which would then get used when they call the
	## :bro:id:`NOTICE` function.  The convention is to give a general category
	## along with the specific notice separating words with underscores and using
	## leading capitals on each word except for abbreviations which are kept in
	## all capitals.  For example, SSH::Login is for heuristically guessed 
	## successful SSH logins.
	type Type: enum {
		## Notice reporting a count of how often a notice occurred.
		Tally,
	};
	
	## These are values representing actions that can be taken with notices.
	type Action: enum {
		## Indicates that the notice should be sent to the notice file.
		ACTION_FILE,
		## Indicates that the notice should be alarmed on.
		ACTION_ALARM,
		## Indicates that the notice should be sent to the configured notice
		## contact email address(es).
		ACTION_EMAIL,
		## Indicates that the notice should be sent to the configured pager 
		## email address.
		ACTION_PAGE,
		## Indicates that no more actions should be found after the policy 
		## item returning this matched.
		ACTION_STOP,
	};
	
	type Info: record {
		ts:             time           &log &optional;
		uid:            string         &log &optional;
		id:             conn_id        &log &optional;
		
		## The victim of the notice.  This can be used in cases where there
		## is a definite loser for a notice.  In cases where there isn't a 
		## victim, this field should be left empty.
		victim:         addr           &log &optional;
		
		## The :bro:enum:`Notice::Type` of the notice.
		note:           Type           &log;
		## The human readable message for the notice.
		msg:            string         &log &optional;
		## Sub-message.
		sub:            string         &log &optional;

		## Source address, if we don't have a connection.
		src:            addr           &log &optional;
		## Destination address.
		dst:            addr           &log &optional;
		## Associated port, if we don't have a connection.
		p:              port           &log &optional;
		## Associated count, or perhaps a status code.
		n:              count          &log &optional;

		## Connection associated with the notice.
		conn:           connection     &optional;
		## Associated ICMP "connection".
		iconn:          icmp_conn      &optional;

		## Peer that raised this notice.
		src_peer:       event_peer     &log &optional;
		## Uniquely identifying tag associated with this notice.
		tag:            string         &log &optional;
		
		## The set of actions that are to be applied to this notice.
		## TODO: there is a problem setting a &default=set() attribute
		##       for sets containing enum values.
		actions:        set[Notice::Action] &log &optional;
	};
	
	## Ignored notice types.
	const ignored_types: set[Notice::Type] = {} &redef;
	## Emailed notice types.
	const emailed_types: set[Notice::Type] = {} &redef;
	
	## This is the record that defines the items that make up the notice policy.
	type PolicyItem: record {
		## Define the priority for this check.  Items are checked in ordered
		## from highest value (10) to lowest value (0).
		priority: count                            &log &default=5;
		## An action given to the notice if the predicate return true.
		result:   Notice::Action                   &log &default=ACTION_FILE;
		## The pred (predicate) field is a function that returns a boolean T 
		## or F value.  If the predicate function return true, the action in 
		## this record is applied to the notice that is given as an argument 
		## to the predicate function.
		pred:     function(n: Notice::Info): bool;
	};
	
	# This is the :bro:id:`Notice::policy` where the local notice conversion 
	# policy is set.
	const policy: set[Notice::PolicyItem] = {
		[$pred(n: Notice::Info) = { return T; },
		 $result = ACTION_FILE,
		 $priority = 0],
		[$pred(n: Notice::Info) = { return (n$note in ignored_types); },
		 $result = ACTION_STOP,
		 $priority = 10],
		[$pred(n: Notice::Info) = { return (n$note in emailed_types); },
		 $result = ACTION_EMAIL,
		 $priority = 9],
	} &redef;
	
	## Local system mail program.
	const mail_script    = "/bin/mail" &redef;
	## Email address to send notices with the :bro:enum:`ACTION_EMAIL` action.
	const mail_dest      = ""          &redef;
	## Email address to send notices with the :bro:enum:`ACTION_PAGE` action.
	const mail_page_dest = ""          &redef;

	## This is the event that is called as the entry point to the 
	## notice framework by the global :bro:id:`NOTICE` function.  By the time 
	## this event is generated, default values have already been filled out in
	## the :bro:type:`Notice::Info` record and synchronous functions in the 
	## :bro:id:`Notice:notice_functions` have already been called.  The notice
	## policy has also been applied.
	global notice: event(n: Info);

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
	
	## Call this function to send a notice in an email.  It is already used
	## by default with the built in :bro:enum:`ACTION_EMAIL` and
	## :bro:enum:`ACTION_PAGE` actions.
	global email_notice_to: function(n: Info, dest: string);
	
	## This is an internally used function, please ignore it.  It's only used
	## for filling out missing details of :bro:type:`Notice:Info` records
	## before the synchronous and asynchronous event pathways have begun.
	global apply_policy: function(n: Notice::Info);
	
	## This event can be handled to access the :bro:type:`Info`
	## record as it is sent on to the logging framework.
	global log_notice: event(rec: Info);
}

# This is an internal variable used to store the notice policy ordered by 
# priority.
global ordered_policy: vector of PolicyItem = vector();


redef record Conn::Info += {
	notice_tags: set[string] &log &optional;
};

event bro_init()
	{
	Log::create_stream(NOTICE_POLICY, [$columns=PolicyItem]);
	
	Log::create_stream(Notice::NOTICE, [$columns=Info, $ev=log_notice]);
	
	# Add a filter to create the alarm log.
	Log::add_filter(Notice::NOTICE, [$name = "alarm", $path = "alarm",
	                          $pred(rec: Notice::Info) = { return (ACTION_ALARM in rec$actions); }]);
	
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

function email_notice_to(n: Notice::Info, dest: string)
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
function apply_policy(n: Notice::Info)
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

	if ( ! n?$src_peer )
		n$src_peer = get_event_peer();
		
	if ( ! n?$actions )
		n$actions = set();
	
	# Generate a unique ID for this notice.
	n$tag = unique_id("@");
	
	for ( i in ordered_policy )
		{
		if ( ordered_policy[i]$pred(n) )
			{
			# If the predicate 
			add n$actions[ordered_policy[i]$result];
			
			# This is the one special case for notice actions because it's
			# acting as a stopper to the notice policy evaluation.
			if ( ordered_policy[i]$result == ACTION_STOP )
				break;
			}
		}
	}
	
event notice(n: Notice::Info) &priority=-5
	{
	if ( ACTION_EMAIL in n$actions )
		email_notice_to(n, mail_dest);
	
	if ( ACTION_PAGE in n$actions )
		email_notice_to(n, mail_page_dest);
	
	# Add the tag to the connection's notice_tags if there is a connection.
	# TODO: figure out how to move this to the conn scripts.  This should 
	#       cause protocols/conn to be a dependency.
	if ( n?$conn && n$conn?$conn )
		{
		if ( ! n$conn$conn?$notice_tags )
			n$conn$conn$notice_tags = set();
		add n$conn$conn$notice_tags[n$tag];
		}
	
	Log::write(Notice::NOTICE, n);
	
@ifdef ( IDMEF_support )
	if ( n?$id )
		generate_idmef(n$id$orig_h, n$id$orig_p, n$id$resp_h, n$id$resp_p);
@endif
	}
	
# Create the ordered notice policy automatically which will be used at runtime 
# for prioritized matching of the notice policy.
event bro_init()
	{
	local tmp: table[count] of set[PolicyItem] = table();
	for ( pi in policy )
		{
		if ( pi$priority < 0 || pi$priority > 10 )
			{
			print "All Notice::PolicyItem priorities must be within 0 and 10";
			exit();
			}
			
		if ( pi$priority !in tmp )
			tmp[pi$priority] = set();
		add tmp[pi$priority][pi];
		}
	
	local rev_count = vector(10,9,8,7,6,5,4,3,2,1,0);
	for ( i in rev_count )
		{
		local j = rev_count[i];
		if ( j in tmp )
			{
			for ( pi in tmp[j] )
				{
				ordered_policy[|ordered_policy|] = pi;
				Log::write(NOTICE_POLICY, pi);
				}
			}
		}
	}

module GLOBAL;

## This is the entry point in the global namespace for notice framework.
function NOTICE(n: Notice::Info)
	{
	# Fill out fields that might be empty and do the policy processing.
	Notice::apply_policy(n);

	# Run the synchronous functions with the notice.
	for ( func in Notice::notice_functions )
		func(n);

	# Generate the notice event with the notice.
	event Notice::notice(n);
	}
