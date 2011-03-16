

module Notice;

export {
	type Type: enum {
		NoticeNone,   # placeholder
		NoticeTally,  # notice reporting count of how often a notice occurred
	};

	type Action: enum {
		# Similar to WeirdAction in weird.bro.
		NOTICE_UNKNOWN,  # placeholder
		NOTICE_IGNORE, NOTICE_ALARM_ALWAYS,
		NOTICE_EMAIL, NOTICE_FILE, NOTICE_PAGE,
		NOTICE_DROP,     # drops the address via Drop::drop_address, and alarms
	};
	
	type Info: record {
		note: Notice::Type;
		msg: string &default="";
		sub: string &optional;	# sub-message

		conn: connection &optional;	# connection associated with notice
		iconn: icmp_conn &optional;	# associated ICMP "connection"
		id: conn_id &optional;	# connection-ID, if we don't have a connection handy
		src: addr &optional;	# source address, if we don't have a connection
		dst: addr &optional;	# destination address
		p: port &optional;	# associated port, if we don't have a conn.

		n: count &optional;  # associated count, or perhaps status code

		# Automatically set attributes.
		action: Notice::Action &default=NOTICE_UNKNOWN; # once action determined
		#src_peer: event_peer &optional;	# source that raised this notice
		#tag: string &optional;	# tag associated with this notice
		#dropped: bool &optional &default=F; # true if src successfully dropped

		# If we asked the Time Machine to capture, the filename prefix.
		#captured: string &optional;

		# If false, don't alarm independent of the determined notice action.
		# If true, alarm dependening on notice action.
		do_alarm: bool &default=T;
	};

	type PolicyItem: record {
		result: Notice::Action &default=NOTICE_FILE;
		pred: function(n: Notice::Info): bool;
		priority: count &default=1;
	};
	
	
	# Variables the control email notification.
	const mail_script = "/bin/mail" &redef;	# local system mail program
	const mail_dest = "" &redef;	# email address to send mail to
	const mail_page_dest = "bro-page" &redef;	# email address of pager
	
	# Do not generate notice_action events for these NOTICE types.
	const suppress_notice_actions: set[Notice::Type] &redef; 
	
	# Hack to suppress duplicate notice_actions for remote notices.
	global suppress_notice_action = F;
	
	
	# This is the Notice::policy where the local notice conversion policy
	# is set.
	const policy: set[Notice::PolicyItem] = {
		[$pred(n: Notice::Info) = { return T; },
		 $result = NOTICE_ALARM_ALWAYS,
		 $priority = 0],
	} &redef;
	
	# Table that maps notices into a function that should be called
	# to determine the action.
	const action_filters:
		table[Notice::Type] of
			function(n: Notice::Info, a: Notice::Action): Notice::Action &redef;
	
	# This should have a high probability of being unique without
	# generating overly long tags.  This is redef'able in case you need
	# determinism in tags (such as for regression testing).
	const notice_tag_prefix =
		fmt("%x-%x-",
		    double_to_count(time_to_double(current_time())) % 255,
		    getpid()) &redef;

	# Likewise redef'able for regression testing.
	const new_notice_tag = function(): string { return ""; } &redef;

	# Function to add a unique NOTICE tag to a connection.  This is done
	# automatically whenever a NOTICE is raised, but sometimes one might need
	# to call this function in advance of that to ensure that the tag appears
	# in the connection summaries (i.e., when connection_state_remove() can be
	# raised before the NOTICE is generated.)
	global tags: table[conn_id] of string;

	# These are implemented below
	global email_notice_to: function(n: Notice::Info, dest: string) &redef;
	global NOTICE: function(n: Notice::Info);
	
}

# Each notice has a unique ID associated with it.
global notice_id = 0;
redef new_notice_tag = function(): string
		{ return fmt("%s%x", notice_tag_prefix, ++notice_id); };

event bro_init()
	{
	Log::create_stream("NOTICE", "Notice::Info");
	Log::add_default_filter("NOTICE");
	}

function add_notice_tag(c: connection): string
	{
	if ( c$id in tags )
		return tags[c$id];

	local tag_id = new_notice_tag();
	append_addl(c, fmt("@%s", tag_id));
	tags[c$id] = tag_id;

	return tag_id;
	}

event delete_notice_tags(c: connection)
	{
	delete tags[c$id];
	}

event connection_state_remove(c: connection) &priority = -10
	{
	event delete_notice_tags(c);
	}

# This handler is useful for processing notices after the notice filters
# have been applied and yielded an Notice::Action.
#
# It's tempting to make the default handler do the logging and
# printing to notice_file, rather than NOTICE.  I hesitate to do that,
# though, because it perhaps could slow down notification, because
# in the absence of event priorities, the event would have to wait
# behind any other already-queued events.

event notice_action(n: Notice::Info, action: Notice::Action)
	{
	}


# Similar to notice_action but only generated if the notice also
# triggers an alarm.
event notice_alarm(n: Notice::Info, action: Notice::Action)
	{
	}

function notice_tags(n: Notice::Info) : table[string] of string
	{
	if ( is_remote_event() )
		{
		#if ( n$src_peer$descr != "" )
		#	{
		#	#tags["es"] = n$src_peer$descr;
		#	}
		#else
		#	{
		#	#tags["es"] = fmt("%s/%s", n$src_peer$host, n$src_peer$p);
		#	}
		}
	else
		{
		#tags["es"] = peer_description;
		}
	#return tags;
	}

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

function email_notice(n: Notice::Info, action: Notice::Action)
	{
	# Choose destination address based on action type.
	local dest = (action == NOTICE_EMAIL) ? mail_dest : mail_page_dest;
	email_notice_to(n, dest);
	}

# Executes a script with all of the notice fields put into the
# new process' environment as "BRO_ARG_<field>" variables.
function execute_with_notice(cmd: string, n: Notice::Info)
	{
	# TODO: fix system calls
	#local tags = tags(n);
	system_env(cmd, tags);
	}

# Can't load it at the beginning due to circular dependencies.
#@load drop

function NOTICE(n: Notice::Info)
	{
	# Fill in some defaults.
	if ( ! n?$id && n?$conn )
		n$id = n$conn$id;

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

	#if ( ! n?$src_peer )
	#	n$src_peer = get_event_peer();

	#if ( n?$conn )
	#	n$tag = add_notice_tag(n$conn);
	#if ( ! n?$tag )
	#	n$tag = new_notice_tag();

	local action = match n using policy;

	if ( action != NOTICE_IGNORE && 
	     action != NOTICE_FILE &&
	     n$note in action_filters )
		action = action_filters[n$note](n, action);

	n$action = action;

	if ( action == NOTICE_EMAIL || action == NOTICE_PAGE )
		email_notice(n, action);

#	if ( action == NOTICE_DROP )
#		{
#		local drop = Drop::drop_address(n$src, "");
#		local addl = drop?$sub ? fmt(" %s", drop$sub) : "";
#		n$dropped = drop$note != Drop::AddressDropIgnored;
#		n$msg += fmt(" [%s%s]", drop$note, addl);
#		}

	if ( action != NOTICE_IGNORE )
		{
		# Build the info here after we had a chance to set the
		# $dropped field.
		Log::write("NOTICE", n);

		if ( action != NOTICE_FILE && n$do_alarm )
			{
			# TODO: alarm may turn into a filter.
			alarm n;
			event notice_alarm(n, action);
			}
		}

@ifdef ( IDMEF_support )
	if ( n?$id )
		generate_idmef(n$id$orig_h, n$id$orig_p,
			       n$id$resp_h, n$id$resp_p);
@endif

	if ( ! suppress_notice_action && n$note !in suppress_notice_actions )
		event notice_action(n, action);
	}


@load notice-action-filters
