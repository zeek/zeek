# $Id: notice.bro 6756 2009-06-14 21:31:19Z vern $

const use_tagging = F &redef;

type Notice: enum {
	NoticeNone,	# placeholder
	NoticeTally,	# notice reporting count of how often a notice occurred
};

type NoticeAction: enum {
	# Similar to WeirdAction in weird.bro.
	NOTICE_UNKNOWN,	# placeholder
	NOTICE_IGNORE, NOTICE_FILE, NOTICE_ALARM_ALWAYS,
	NOTICE_EMAIL, NOTICE_PAGE,
	NOTICE_DROP,	# drops the address via Drop::drop_address, and alarms
};


type notice_info: record {
	note: Notice;
	msg: string &default="";
	sub: string &optional;	# sub-message

	conn: connection &optional;	# connection associated with notice
	iconn: icmp_conn &optional;	# associated ICMP "connection"
	id: conn_id &optional;	# connection-ID, if we don't have a connection handy
	src: addr &optional;	# source address, if we don't have a connection
	dst: addr &optional;	# destination address

	p: port &optional;	# associated port, if we don't have a conn.

	# The following are detailed attributes that are associated with some
	# notices, but not all.

	user: string &optional;

	filename: string &optional;

	method: string &optional;
	URL: string &optional;

	n: count &optional;	# associated count, or perhaps status code

	aux: table[string] of string &optional;	# further NOTICE-specific data

	# Automatically set attributes.
	action: NoticeAction &default=NOTICE_UNKNOWN; # once action determined
	src_peer: event_peer &optional;	# source that raised this notice
	tag: string &optional;	# tag associated with this notice
	dropped: bool &optional &default=F; # true if src successfully dropped

	# If we asked the Time Machine to capture, the filename prefix.
	captured: string &optional;

	# If false, don't alarm independent of the determined notice action.
	# If true, alarm dependening on notice action.
	do_alarm: bool &default=T;

};

type notice_policy_item: record {
	result: NoticeAction &default=NOTICE_FILE;
	pred: function(n: notice_info): bool;
	priority: count &default=1;
};

global notice_policy: set[notice_policy_item] = {
	[$pred(n: notice_info) = { return T; },
	 $result = NOTICE_ALARM_ALWAYS,
	 $priority = 0],
} &redef;

global NOTICE: function(n: notice_info);

# Variables the control email notification.
const mail_script = "/bin/mail" &redef;	# local system mail program
const mail_dest = "" &redef;	# email address to send mail to
const mail_page_dest = "bro-page" &redef;	# email address of pager


# Table that maps notices into a function that should be called
# to determine the action.
global notice_action_filters:
	table[Notice] of
		function(n: notice_info, a: NoticeAction): NoticeAction &redef;


# Each notice has a unique ID associated with it.
global notice_id = 0;

# This should have a high probability of being unique without
# generating overly long tags.  This is redef'able in case you need
# determinism in tags (such as for regression testing).
global notice_tag_prefix =
		fmt("%x-%x-",
			double_to_count(time_to_double(current_time())) % 255,
			getpid())
		&redef;

# Likewise redef'able for regression testing.
global new_notice_tag =
	function(): string
		{
		return fmt("%s%x", notice_tag_prefix, ++notice_id);
		}
	&redef;

# Function to add a unique NOTICE tag to a connection.  This is done
# automatically whenever a NOTICE is raised, but sometimes one might need
# to call this function in advance of that to ensure that the tag appears
# in the connection summaries (i.e., when connection_state_remove() can be
# raised before the NOTICE is generated.)
global notice_tags: table[conn_id] of string;

function add_notice_tag(c: connection): string
	{
	if ( c$id in notice_tags )
		return notice_tags[c$id];

	local tag_id = new_notice_tag();
	append_addl(c, fmt("@%s", tag_id));
	notice_tags[c$id] = tag_id;

	return tag_id;
	}

event delete_notice_tags(c: connection)
	{
	delete notice_tags[c$id];
	}

event connection_state_remove(c: connection)
	{
	# We do not delete the tag right here because there may be other
	# connection_state_remove handlers invoked after us which
	# want to generate a notice.
	schedule 1 secs { delete_notice_tags(c) };
	}

const notice_file = open_log_file("notice") &redef;

# This handler is useful for processing notices after the notice filters
# have been applied and yielded an NoticeAction.
#
# It's tempting to make the default handler do the logging and
# printing to notice_file, rather than NOTICE.  I hesitate to do that,
# though, because it perhaps could slow down notification, because
# in the absence of event priorities, the event would have to wait
# behind any other already-queued events.

event notice_action(n: notice_info, action: NoticeAction)
	{
	}

# Do not generate notice_action events for these NOTICE types.
global suppress_notice_actions: set[Notice] &redef; 

# Similar to notice_action but only generated if the notice also
# triggers an alarm.
event notice_alarm(n: notice_info, action: NoticeAction)
	{
	}

# Hack to suppress duplicate notice_actions for remote notices.
global suppress_notice_action = F;

function notice_info_tags(n: notice_info) : table[string] of string
	{
	local tags: table[string] of string;

	local t = is_remote_event() ? current_time() : network_time();
	tags["t"] = fmt("%.06f", t);
	tags["no"] = fmt("%s", n$note);
	tags["na"] = fmt("%s", n$action);
	tags["sa"] = n?$src ? fmt("%s", n$src) : "";
	tags["sp"] = n?$id && n$id$orig_h == n$src ? fmt("%s", n$id$orig_p) : "";
	tags["da"] = n?$dst ? fmt("%s", n$dst) : "";
	tags["dp"] = n?$id && n$id$resp_h == n$dst ? fmt("%s", n$id$resp_p) : "";
	tags["p"] = n?$p ? fmt("%s", n$p) : "";
	tags["user"] = n?$user ? n$user : "";
	tags["file"] = n?$filename ? n$filename : "";
	tags["method"] =  n?$method ? n$method : "";
	tags["url"] = n?$URL ? n$URL : "";
	tags["num"] = n?$n ? fmt("%s", n$n) : "";
	tags["msg"] = n?$msg ? n$msg : "";
	tags["sub"] = n?$sub ? n$sub : "";
	tags["captured"] = n?$captured ? n$captured : "";
	tags["tag"] = fmt("@%s", n$tag);
	tags["dropped"] = n$dropped ? "1" : "";

	if ( n?$aux )
		{
		for ( a in n$aux )
			tags[fmt("aux_%s", a)] = n$aux[a];
		}

	if ( is_remote_event() )
		{
		if ( n$src_peer$descr != "" )
			tags["es"] = n$src_peer$descr;
		else
			tags["es"] = fmt("%s/%s", n$src_peer$host, n$src_peer$p);
		}

	else
		tags["es"] = peer_description;

	return tags;
	}

function build_notice_info_string_untagged(n: notice_info) : string
	{
	# We add the fields in this order. Fields not listed won't be added.
	local fields = vector("t", "no", "na", "es", "sa", "sp", "da", "dp", 
		"user", "file", "method", "url", "num", "msg", "sub", "tag");

	local tags = notice_info_tags(n);
	local cur_info = "";

	for ( i in fields )
		{
		local val = tags[fields[i]];
		val = string_escape(val, ":");

		if ( cur_info == "" )
			cur_info = val;
		else
			cur_info = fmt("%s:%s", cur_info, val);
		}

	return cur_info;
	}

function build_notice_info_string_tagged(n: notice_info) : string
	{
	# We add the fields in this order. Fields not listed won't be added
	# (except aux_*).
	local fields = vector("t", "no", "na", "dropped", "es", "sa", "sp",
			"da", "dp", "p", "user", "file", "method", "url",
			"num", "msg", "sub", "captured", "tag");

	local tags = notice_info_tags(n);
	local cur_info = "";

	for ( i in fields )
		{
		local val = tags[fields[i]];
		local f = fields[i];

		if ( val == "" )
			next;

		val = string_escape(val, "= ");

		if ( cur_info == "" )
			cur_info = fmt("%s=%s", f, val);
		else
			cur_info = fmt("%s %s=%s", cur_info, f, val);
		}

	for ( t in tags )
		{
		if ( t == /aux_.*/ )
			{
			if ( cur_info == "" )
				cur_info = fmt("%s=%s", t, tags[t]);
			else
				cur_info = fmt("%s %s=%s", cur_info, t, tags[t]);
			}
		}

	return cur_info;
	}

function email_notice_to(n: notice_info, dest: string)
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

function email_notice(n: notice_info, action: NoticeAction)
	{
	# Choose destination address based on action type.
	local destination =
		(action == NOTICE_EMAIL) ?  mail_dest : mail_page_dest;

	email_notice_to(n, destination);
	}

# Executes a script with all of the notice fields put into the
# new process' environment as "BRO_ARG_<field>" variables.
function execute_with_notice(cmd: string, n: notice_info)
	{
	local tags = notice_info_tags(n);
	system_env(cmd, tags);
	}

# Can't load it at the beginning due to circular dependencies.
@load drop

function NOTICE(n: notice_info)
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

	if ( ! n?$src_peer )
		n$src_peer = get_event_peer();

	if ( n?$conn )
		n$tag = add_notice_tag(n$conn);

	if ( ! n?$tag )
		n$tag = new_notice_tag();

	local action = match n using notice_policy;

	local n_id = "";

	if ( action != NOTICE_IGNORE && action != NOTICE_FILE &&
		n$note in notice_action_filters )
		action = notice_action_filters[n$note](n, action);

	n$action = action;

	if ( action == NOTICE_EMAIL || action == NOTICE_PAGE )
		email_notice(n, action);

	if ( action == NOTICE_DROP )
		{
		local drop = Drop::drop_address(n$src, "");
		local addl = drop?$sub ? fmt(" %s", drop$sub) : "";
		n$dropped = drop$note != Drop::AddressDropIgnored;
		n$msg += fmt(" [%s%s]", drop$note, addl);
		}

	if ( action != NOTICE_IGNORE )
		{
		# Build the info here after we had a chance to set the
		# $dropped field.
		local info: string;
		if ( use_tagging )
			info = build_notice_info_string_tagged(n);
		else
			info = build_notice_info_string_untagged(n);

		print notice_file, info;

		if ( action != NOTICE_FILE && n$do_alarm )
			{
			if ( use_tagging )
				{
				alarm info;
				event notice_alarm(n, action);
				}
			else
				{
				local descr = "";
				if ( is_remote_event() )
					{
					if ( n$src_peer$descr != "" )
						descr = fmt("<%s> ",
							n$src_peer$descr);
					else
						descr = fmt("<%s:%s> ",
							n$src_peer$host,
							n$src_peer$p);
					}

				alarm fmt("%s %s%s", n$note, descr, n$msg);
				event notice_alarm(n, action);
				}
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
