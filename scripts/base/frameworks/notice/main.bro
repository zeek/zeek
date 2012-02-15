##! This is the notice framework which enables Bro to "notice" things which
##! are odd or potentially bad.  Decisions of the meaning of various notices
##! need to be done per site because Bro does not ship with assumptions about
##! what is bad activity for sites.  More extensive documetation about using
##! the notice framework can be found in :doc:`/notice`.

module Notice;

export {
	redef enum Log::ID += {
		## This is the primary logging stream for notices.
		LOG,
		## This is the notice policy auditing log.  It records what the current
		## notice policy is at Bro init time.
		POLICY_LOG,
		## This is the alarm stream.
		ALARM_LOG,
	};

	## Scripts creating new notices need to redef this enum to add their own
	## specific notice types which would then get used when they call the
	## :bro:id:`NOTICE` function.  The convention is to give a general category
	## along with the specific notice separating words with underscores and
	## using leading capitals on each word except for abbreviations which are
	## kept in all capitals.  For example, SSH::Login is for heuristically
	## guessed successful SSH logins.
	type Type: enum {
		## Notice reporting a count of how often a notice occurred.
		Tally,
	};

	## These are values representing actions that can be taken with notices.
	type Action: enum {
		## Indicates that there is no action to be taken.
		ACTION_NONE,
		## Indicates that the notice should be sent to the notice logging stream.
		ACTION_LOG,
		## Indicates that the notice should be sent to the email address(es)
		## configured in the :bro:id:`Notice::mail_dest` variable.
		ACTION_EMAIL,
		## Indicates that the notice should be alarmed.  A readable ASCII
		## version of the alarm log is emailed in bulk to the address(es)
		## configured in :bro:id:`Notice::mail_dest`.
		ACTION_ALARM,
		## Indicates that the notice should not be supressed by the normal
		## duplicate notice suppression that the notice framework does.
		ACTION_NO_SUPPRESS,
	};

	## The notice framework is able to do automatic notice supression by
	## utilizing the $identifier field in :bro:type:`Notice::Info` records.
	## Set this to "0secs" to completely disable automated notice suppression.
	const default_suppression_interval = 1hrs &redef;

	type Info: record {
		## An absolute time indicating when the notice occurred, defaults
		## to the current network time.
		ts:             time           &log &optional;

		## A connection UID which uniquely identifies the endpoints
		## concerned with the notice.
		uid:            string         &log &optional;

		## A connection 4-tuple identifying the endpoints concerned with the
		## notice.
		id:             conn_id        &log &optional;
		
		## A shorthand way of giving the uid and id to a notice.  The
		## reference to the actual connection will be deleted after applying
		## the notice policy.
		conn:           connection     &optional;
		## A shorthand way of giving the uid and id to a notice.  The
		## reference to the actual connection will be deleted after applying
		## the notice policy.
		iconn:          icmp_conn      &optional;

		## The transport protocol. Filled automatically when either conn, iconn
		## or p is specified.
		proto:          transport_proto &log &optional;

		## The :bro:type:`Notice::Type` of the notice.
		note:           Type           &log;
		## The human readable message for the notice.
		msg:            string         &log &optional;
		## The human readable sub-message.
		sub:            string         &log &optional;

		## Source address, if we don't have a :bro:type:`conn_id`.
		src:            addr           &log &optional;
		## Destination address.
		dst:            addr           &log &optional;
		## Associated port, if we don't have a :bro:type:`conn_id`.
		p:              port           &log &optional;
		## Associated count, or perhaps a status code.
		n:              count          &log &optional;

		## Peer that raised this notice.
		src_peer:       event_peer     &optional;
		## Textual description for the peer that raised this notice.
		peer_descr:     string         &log &optional;

		## The actions which have been applied to this notice.
		actions:        set[Notice::Action] &log &optional;

		## These are policy items that returned T and applied their action
		## to the notice.
		policy_items:   set[count]     &log &optional;

		## By adding chunks of text into this element, other scripts can
		## expand on notices that are being emailed.  The normal way to add text
		## is to extend the vector by handling the :bro:id:`Notice::notice`
		## event and modifying the notice in place.
		email_body_sections:  vector of string &optional;

		## Adding a string "token" to this set will cause the notice framework's
		## built-in emailing functionality to delay sending the email until
		## either the token has been removed or the email has been delayed
		## for :bro:id:`Notice::max_email_delay`.
		email_delay_tokens:   set[string] &optional;

		## This field is to be provided when a notice is generated for the
		## purpose of deduplicating notices.  The identifier string should
		## be unique for a single instance of the notice.  This field should be
		## filled out in almost all cases when generating notices to define
		## when a notice is conceptually a duplicate of a previous notice.
		##
		## For example, an SSL certificate that is going to expire soon should
		## always have the same identifier no matter the client IP address
		## that connected and resulted in the certificate being exposed.  In
		## this case, the resp_h, resp_p, and hash of the certificate would be
		## used to create this value.  The hash of the cert is included
		## because servers can return multiple certificates on the same port.
		##
		## Another example might be a host downloading a file which triggered
		## a notice because the MD5 sum of the file it downloaded was known
		## by some set of intelligence.  In that case, the orig_h (client)
		## and MD5 sum would be used in this field to dedup because if the
		## same file is downloaded over and over again you really only want to
		## know about it a single time.  This makes it possible to send those
		## notices to email without worrying so much about sending thousands
		## of emails.
		identifier:          string         &optional;

		## This field indicates the length of time that this
		## unique notice should be suppressed.  This field is automatically
		## filled out and should not be written to by any other script.
		suppress_for:        interval       &log &optional;
	};

	## Ignored notice types.
	const ignored_types: set[Notice::Type] = {} &redef;
	## Emailed notice types.
	const emailed_types: set[Notice::Type] = {} &redef;
	## Alarmed notice types.
	const alarmed_types: set[Notice::Type] = {} &redef;
	## Types that should be suppressed for the default suppression interval.
	const not_suppressed_types: set[Notice::Type] = {} &redef;
	## This table can be used as a shorthand way to modify suppression
	## intervals for entire notice types.
	const type_suppression_intervals: table[Notice::Type] of interval = {} &redef;

	## This is the record that defines the items that make up the notice policy.
	type PolicyItem: record {
		## This is the exact positional order in which the
		## :bro:type:`Notice::PolicyItem` records are checked.
		## This is set internally by the notice framework.
		position: count                            &log &optional;
		## Define the priority for this check.  Items are checked in ordered
		## from highest value (10) to lowest value (0).
		priority: count                            &log &default=5;
		## An action given to the notice if the predicate return true.
		action:   Notice::Action                   &log &default=ACTION_NONE;
		## The pred (predicate) field is a function that returns a boolean T
		## or F value.  If the predicate function return true, the action in
		## this record is applied to the notice that is given as an argument
		## to the predicate function.  If no predicate is supplied, it's
		## assumed that the PolicyItem always applies.
		pred:     function(n: Notice::Info): bool  &log &optional;
		## Indicates this item should terminate policy processing if the
		## predicate returns T.
		halt:     bool                             &log &default=F;
		## This defines the length of time that this particular notice should
		## be supressed.
		suppress_for: interval                     &log &optional;
	};
	
	## Defines a notice policy that is extensible on a per-site basis.
	## All notice processing is done through this variable.
	const policy: set[PolicyItem] = {
		[$pred(n: Notice::Info) = { return (n$note in Notice::ignored_types); },
		 $halt=T, $priority = 9],
		[$pred(n: Notice::Info) = { return (n$note in Notice::not_suppressed_types); },
		 $action = ACTION_NO_SUPPRESS,
		 $priority = 9],
		[$pred(n: Notice::Info) = { return (n$note in Notice::alarmed_types); },
		 $action = ACTION_ALARM,
		 $priority = 8],
		[$pred(n: Notice::Info) = { return (n$note in Notice::emailed_types); },
		 $action = ACTION_EMAIL,
		 $priority = 8],
		[$pred(n: Notice::Info) = {
			if (n$note in Notice::type_suppression_intervals)
				{
				n$suppress_for=Notice::type_suppression_intervals[n$note];
				return T;
				}
			return F;
		 },
		 $action = ACTION_NONE,
		 $priority = 8],
		[$action = ACTION_LOG,
		 $priority = 0],
	} &redef;

	## Local system sendmail program.
	const sendmail            = "/usr/sbin/sendmail" &redef;
	## Email address to send notices with the :bro:enum:`Notice::ACTION_EMAIL`
	## action or to send bulk alarm logs on rotation with
	## :bro:enum:`Notice::ACTION_ALARM`.
	const mail_dest           = ""                   &redef;

	## Address that emails will be from.
	const mail_from           = "Big Brother <bro@localhost>" &redef;
	## Reply-to address used in outbound email.
	const reply_to            = "" &redef;
	## Text string prefixed to the subject of all emails sent out.
	const mail_subject_prefix = "[Bro]" &redef;
	## The maximum amount of time a plugin can delay email from being sent.
	const max_email_delay     = 15secs &redef;

	## A log postprocessing function that implements emailing the contents
	## of a log upon rotation to any configured :bro:id:`Notice::mail_dest`.
	## The rotated log is removed upon being sent.
	##
	## info: A record containing the rotated log file information.
	##
	## Returns: True.
	global log_mailing_postprocessor: function(info: Log::RotationInfo): bool;

	## This is the event that is called as the entry point to the
	## notice framework by the global :bro:id:`NOTICE` function.  By the time
	## this event is generated, default values have already been filled out in
	## the :bro:type:`Notice::Info` record and synchronous functions in the 
	## :bro:id:`Notice::sync_functions` have already been called.  The notice
	## policy has also been applied.
	##
	## n: The record containing notice data.
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
	const sync_functions: set[function(n: Notice::Info)] = set() &redef;

	## This event is generated when a notice begins to be suppressed.
	##
	## n: The record containing notice data regarding the notice type
	##    about to be suppressed.
	global begin_suppression: event(n: Notice::Info);

	## This event is generated on each occurence of an event being suppressed.
	##
	## n: The record containing notice data regarding the notice type
	##    being suppressed.
	global suppressed: event(n: Notice::Info);

	## This event is generated when a notice stops being suppressed.
	##
	## n: The record containing notice data regarding the notice type
	##    that was being suppressed.
	global end_suppression: event(n: Notice::Info);

	## Call this function to send a notice in an email.  It is already used
	## by default with the built in :bro:enum:`Notice::ACTION_EMAIL` and
	## :bro:enum:`Notice::ACTION_PAGE` actions.
	##
	## n: The record of notice data to email.
	##
	## dest: The intended recipient of the notice email.
	##
	## extend: Whether to extend the email using the ``email_body_sections``
	##         field of *n*.
	global email_notice_to: function(n: Info, dest: string, extend: bool);

	## Constructs mail headers to which an email body can be appended for
	## sending with sendmail.
	##
	## subject_desc: a subject string to use for the mail
	##
	## dest: recipient string to use for the mail
	##
	## Returns: a string of mail headers to which an email body can be appended
	global email_headers: function(subject_desc: string, dest: string): string;
	
	## This event can be handled to access the :bro:type:`Notice::Info`
	## record as it is sent on to the logging framework.
	##
	## rec: The record containing notice data before it is logged.
	global log_notice: event(rec: Info);
	
	## This is an internal wrapper for the global :bro:id:`NOTICE` function;
	## disregard.
	##
	## n: The record of notice data.
	global internal_NOTICE: function(n: Notice::Info);
}

# This is used as a hack to implement per-item expiration intervals.
function per_notice_suppression_interval(t: table[Notice::Type, string] of Notice::Info, idx: any): interval
	{
	local n: Notice::Type;
	local s: string;
	[n,s] = idx;

	local suppress_time = t[n,s]$suppress_for - (network_time() - t[n,s]$ts);
	if ( suppress_time < 0secs )
		suppress_time = 0secs;

	# If there is no more suppression time left, the notice needs to be sent
	# to the end_suppression event.
	if ( suppress_time == 0secs )
		event Notice::end_suppression(t[n,s]);

	return suppress_time;
	}

# This is the internally maintained notice suppression table.  It's
# indexed on the Notice::Type and the $identifier field from the notice.
global suppressing: table[Type, string] of Notice::Info = {}
		&create_expire=0secs
		&expire_func=per_notice_suppression_interval;

# This is an internal variable used to store the notice policy ordered by
# priority.
global ordered_policy: vector of PolicyItem = vector();

function log_mailing_postprocessor(info: Log::RotationInfo): bool
	{
	if ( ! reading_traces() && mail_dest != "" )
		{
		local headers = email_headers(fmt("Log Contents: %s", info$fname),
		                              mail_dest);
		local tmpfilename = fmt("%s.mailheaders.tmp", info$fname);
		local tmpfile = open(tmpfilename);
		write_file(tmpfile, headers);
		close(tmpfile);
		system(fmt("/bin/cat %s %s | %s -t -oi && /bin/rm %s %s",
		       tmpfilename, info$fname, sendmail, tmpfilename, info$fname));
		}
	return T;
	}

event bro_init() &priority=5
	{
	Log::create_stream(Notice::LOG, [$columns=Info, $ev=log_notice]);

	Log::create_stream(Notice::ALARM_LOG, [$columns=Notice::Info]);
	# If Bro is configured for mailing notices, set up mailing for alarms.
	# Make sure that this alarm log is also output as text so that it can
	# be packaged up and emailed later.
	if ( ! reading_traces() && mail_dest != "" )
		Log::add_filter(Notice::ALARM_LOG,
		    [$name="alarm-mail", $path="alarm-mail", $writer=Log::WRITER_ASCII,
		     $interv=24hrs, $postprocessor=log_mailing_postprocessor]);
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

function email_headers(subject_desc: string, dest: string): string
	{
	local header_text = string_cat(
		"From: ", mail_from, "\n",
		"Subject: ", mail_subject_prefix, " ", subject_desc, "\n",
		"To: ", dest, "\n",
		"User-Agent: Bro-IDS/", bro_version(), "\n");
	if ( reply_to != "" )
		header_text = string_cat(header_text, "Reply-To: ", reply_to, "\n");
	return header_text;
	}

event delay_sending_email(n: Notice::Info, dest: string, extend: bool)
	{
	email_notice_to(n, dest, extend);
	}

function email_notice_to(n: Notice::Info, dest: string, extend: bool)
	{
	if ( reading_traces() || dest == "" )
		return;

	if ( extend )
		{
		if ( |n$email_delay_tokens| > 0 )
			{
			# If we still are within the max_email_delay, keep delaying.
			if ( n$ts + max_email_delay > network_time() )
				{
				schedule 1sec { delay_sending_email(n, dest, extend) };
				return;
				}
			else
				{
				event reporter_info(network_time(),
					fmt("Notice email delay tokens weren't released in time (%s).", n$email_delay_tokens),
					"");
				}
			}
		}

	local email_text = email_headers(fmt("%s", n$note), dest);

	# First off, finish the headers and include the human readable messages
	# then leave a blank line after the message.
	email_text = string_cat(email_text, "\nMessage: ", n$msg);
	if ( n?$sub )
		email_text = string_cat(email_text, "\nSub-message: ", n$sub);

	email_text = string_cat(email_text, "\n\n");

	# Next, add information about the connection if it exists.
	if ( n?$id )
		{
		email_text = string_cat(email_text, "Connection: ",
			fmt("%s", n$id$orig_h), ":", fmt("%d", n$id$orig_p), " -> ",
			fmt("%s", n$id$resp_h), ":", fmt("%d", n$id$resp_p), "\n");
		if ( n?$uid )
			email_text = string_cat(email_text, "Connection uid: ", n$uid, "\n");
		}
	else if ( n?$src )
		email_text = string_cat(email_text, "Address: ", fmt("%s", n$src), "\n");

	# Add the extended information if it's requested.
	if ( extend )
		{
		email_text = string_cat(email_text, "\nEmail Extensions\n");
		email_text = string_cat(email_text,   "----------------\n");
		for ( i in n$email_body_sections )
			{
			email_text = string_cat(email_text, n$email_body_sections[i], "\n");
			}
		}

	email_text = string_cat(email_text, "\n\n--\n[Automatically generated]\n\n");
	piped_exec(fmt("%s -t -oi", sendmail), email_text);
	}

event notice(n: Notice::Info) &priority=-5
	{
	if ( ACTION_EMAIL in n$actions )
		email_notice_to(n, mail_dest, T);
	if ( ACTION_LOG in n$actions )
		Log::write(Notice::LOG, n);
	if ( ACTION_ALARM in n$actions )
		Log::write(Notice::ALARM_LOG, n);

	# Normally suppress further notices like this one unless directed not to.
	#  n$identifier *must* be specified for suppression to function at all.
	if ( n?$identifier &&
	     ACTION_NO_SUPPRESS !in n$actions &&
	     [n$note, n$identifier] !in suppressing &&
	     n$suppress_for != 0secs )
		{
		suppressing[n$note, n$identifier] = n;
		event Notice::begin_suppression(n);
		}
	}
	
## This determines if a notice is being suppressed.  It is only used 
## internally as part of the mechanics for the global :bro:id:`NOTICE`
## function.
function is_being_suppressed(n: Notice::Info): bool
	{
	if ( n?$identifier && [n$note, n$identifier] in suppressing )
		{
		event Notice::suppressed(n);
		return T;
		}
	else
		return F;
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
	if ( ! n?$ts )
		n$ts = network_time();

	if ( n?$conn )
		{
		if ( ! n?$id )
			n$id = n$conn$id;
		if ( ! n?$uid )
			n$uid = n$conn$uid;
		}

	if ( n?$id )
		{
		if ( ! n?$src  )
			n$src = n$id$orig_h;
		if ( ! n?$dst )
			n$dst = n$id$resp_h;
		if ( ! n?$p )
			n$p = n$id$resp_p;
		}

	if ( n?$p ) 
		n$proto = get_port_transport_proto(n$p);

	if ( n?$iconn )
		{
		n$proto = icmp;
		if ( ! n?$src )
			n$src = n$iconn$orig_h;
		if ( ! n?$dst )
			n$dst = n$iconn$resp_h;
		}

	if ( ! n?$src_peer )
		n$src_peer = get_event_peer();
	if ( ! n?$peer_descr )
		n$peer_descr = n$src_peer?$descr ?
		                   n$src_peer$descr : fmt("%s", n$src_peer$host);

	if ( ! n?$actions )
		n$actions = set();

	if ( ! n?$email_body_sections )
		n$email_body_sections = vector();
	if ( ! n?$email_delay_tokens )
		n$email_delay_tokens = set();

	if ( ! n?$policy_items )
		n$policy_items = set();

	for ( i in ordered_policy )
		{
		# If there's no predicate or the predicate returns F.
		if ( ! ordered_policy[i]?$pred || ordered_policy[i]$pred(n) )
			{
			add n$actions[ordered_policy[i]$action];
			add n$policy_items[int_to_count(i)];

			# If the predicate matched and there was a suppression interval,
			# apply it to the notice now.
			if ( ordered_policy[i]?$suppress_for )
				n$suppress_for = ordered_policy[i]$suppress_for;

			# If the policy item wants to halt policy processing, do it now!
			if ( ordered_policy[i]$halt )
				break;
			}
		}

	# Apply the suppression time after applying the policy so that policy
	# items can give custom suppression intervals.  If there is no
	# suppression interval given yet, the default is applied.
	if ( ! n?$suppress_for )
		n$suppress_for = default_suppression_interval;

	# Delete the connection record if it's there so we aren't sending that
	# to remote machines.  It can cause problems due to the size of the
	# connection record.
	if ( n?$conn )
		delete n$conn;
	if ( n?$iconn )
		delete n$iconn;
	}

# Create the ordered notice policy automatically which will be used at runtime
# for prioritized matching of the notice policy.
event bro_init() &priority=10
	{
	# Create the policy log here because it's only written to in this handler.
	Log::create_stream(Notice::POLICY_LOG, [$columns=PolicyItem]);

	local tmp: table[count] of set[PolicyItem] = table();
	for ( pi in policy )
		{
		if ( pi$priority < 0 || pi$priority > 10 )
			Reporter::fatal("All Notice::PolicyItem priorities must be within 0 and 10");

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
				pi$position = |ordered_policy|;
				ordered_policy[|ordered_policy|] = pi;
				Log::write(Notice::POLICY_LOG, pi);
				}
			}
		}
	}

function internal_NOTICE(n: Notice::Info)
	{
	# Suppress this notice if necessary.
	if ( is_being_suppressed(n) )
		return;

	# Fill out fields that might be empty and do the policy processing.
	apply_policy(n);

	# Run the synchronous functions with the notice.
	for ( func in sync_functions )
		func(n);

	# Generate the notice event with the notice.
	event Notice::notice(n);
	}

module GLOBAL;

## This is the entry point in the global namespace for notice framework.
function NOTICE(n: Notice::Info)
	{
	Notice::internal_NOTICE(n);
	}
