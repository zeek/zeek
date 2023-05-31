##! Notice extension that mails out a pretty-printed version of notice_alarm.log
##! in regular intervals, formatted for better human readability. If activated,
##! that replaces the default summary mail having the raw log output.

@load base/frameworks/cluster
@load ../main

module Notice;

export {
	## Activate pretty-printed alarm summaries.
	const pretty_print_alarms = T &redef;

	## Address to send the pretty-printed reports to. Default if not set is
	## :zeek:id:`Notice::mail_dest`.
	##
	## Note that this is overridden by the ZeekControl MailAlarmsTo option.
	const mail_dest_pretty_printed = "" &redef;
	## If an address from one of these networks is reported, we mark
	## the entry with an additional quote symbol (i.e., ">"). Many MUAs
	## then highlight such lines differently.
	global flag_nets: set[subnet] &redef;

	## Function that renders a single alarm. Can be overridden.
	global pretty_print_alarm: function(out: file, n: Info) &redef;

	## Force generating mail file, even if reading from traces or no mail
	## destination is defined. This is mainly for testing.
	global force_email_summaries = F &redef;
}

# We maintain an old-style file recording the pretty-printed alarms.
const  pp_alarms_name = "alarm-mail.txt";
global pp_alarms: file;
global pp_alarms_open: bool = F;

# Returns True if pretty-printed alarm summaries are activated.
function want_pp() : bool
	{
	if ( force_email_summaries )
		return T;

	return (pretty_print_alarms && ! reading_traces()
		&& (mail_dest != "" || mail_dest_pretty_printed != ""));
	}

# Opens and initializes the output file.
function pp_open()
	{
	if ( pp_alarms_open )
		return;

	pp_alarms_open = T;
	pp_alarms = open(pp_alarms_name);
	}

# Closes and mails out the current output file.
function pp_send(rinfo: Log::RotationInfo)
	{
	if ( ! pp_alarms_open )
		return;

	write_file(pp_alarms, "\n\n--\n[Automatically generated]\n\n");
	close(pp_alarms);
	pp_alarms_open = F;

	local from = strftime("%H:%M:%S", rinfo$open);
	local to = strftime("%H:%M:%S", rinfo$close);
	local subject = fmt("Alarm summary from %s-%s", from, to);
	local dest = mail_dest_pretty_printed != "" ? mail_dest_pretty_printed
		: mail_dest;

	if ( dest == "" )
		# No mail destination configured, just leave the file alone. This is mainly for
		# testing.
		return;

	local headers = email_headers(subject, dest);

	local header_name = pp_alarms_name + ".tmp";
	local header = open(header_name);
	write_file(header, headers + "\n");
	close(header);

	system(fmt("/bin/cat %s %s | %s -t -oi && /bin/rm -f %s %s",
		   header_name, pp_alarms_name, sendmail, header_name, pp_alarms_name));
	}

# Postprocessor function that triggers the email.
function pp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( want_pp() )
		pp_send(info);

	return T;
	}

event zeek_init()
	{
	if ( ! want_pp() )
		return;

	# This replaces the standard non-pretty-printing filter.
	Log::add_filter(Notice::ALARM_LOG,
			[$name="alarm-mail", $writer=Log::WRITER_NONE,
			 $interv=Log::default_mail_alarms_interval,
			 $postprocessor=pp_postprocessor]);
	}

hook notice(n: Notice::Info) &priority=-5
	{
	if ( ! want_pp() )
		return;

	if ( ACTION_ALARM !in n$actions )
		return;

	if ( ! pp_alarms_open )
		pp_open();

	pretty_print_alarm(pp_alarms, n);
	}

function do_msg(out: file, n: Info, line1: string, line2: string, line3: string, host1: addr, name1: string, host2: addr, name2: string)
	{
	local country = "";
@ifdef ( Notice::ACTION_ADD_GEODATA ) # Make tests happy, cyclic dependency.
	if ( n?$remote_location && n$remote_location?$country_code  )
		country = fmt(" (remote location %s)", n$remote_location$country_code);
@endif

	line1 = cat(line1, country);

	local resolved = "";

	if ( host1 != 0.0.0.0 )
		resolved = fmt("%s   # %s = %s", resolved, host1, name1);

	if ( host2 != 0.0.0.0 )
		resolved = fmt("%s  %s = %s", resolved, host2, name2);

	print out, line1;
	print out, line2;
	if ( line3 != "" )
		print out, line3;
	if ( resolved != "" )
		print out, resolved;
	print out, "";
	}

# Default pretty-printer.
function pretty_print_alarm(out: file, n: Info)
	{
	local pdescr = "";

@if ( Cluster::is_enabled() )
	pdescr = "local";

	if ( n?$peer_descr )
		pdescr = n$peer_descr;
	else if ( n?$peer_name )
		pdescr = n$peer_name;

	pdescr = fmt("<%s> ", pdescr);
@endif

	local msg = fmt( "%s%s", pdescr, n$msg);

	local who = "";
	local h1 = 0.0.0.0;
	local h2 = 0.0.0.0;

	local orig_p = "";
	local resp_p = "";

	if ( n?$id )
		{
		h1 = n$id$orig_h;
		h2 = n$id$resp_h;
		who = fmt("%s:%s -> %s:%s", h1, n$id$orig_p, h2, n$id$resp_p);
		}
	else if ( n?$src && n?$dst )
		{
		h1 = n$src;
		h2 = n$dst;
		who = fmt("%s -> %s", h1, h2);
		}
	else if ( n?$src )
		{
		h1 = n$src;
		who = fmt("%s%s", h1, (n?$p ? fmt(":%s", n$p) : ""));
		}

	if ( n?$uid )
		who = fmt("%s (uid %s)", who, n$uid );

	local flag = (h1 in flag_nets || h2 in flag_nets);

	local line1 = fmt(">%s %D %s %s", (flag ? ">" : " "), network_time(), n$note, who);
	local line2 = fmt("   %s", msg);
	local line3 = n?$sub ? fmt("   %s", n$sub) : "";

	if ( h1 == 0.0.0.0 )
		{
		do_msg(out, n, line1, line2, line3, h1, "", h2, "");
		return;
		}

	if ( reading_traces() )
		{
		do_msg(out, n, line1, line2, line3, h1, "<skipped>", h2, "<skipped>");
		return;
		}

	when [out, n, h1, h2, line1, line2, line3] ( local h1name = lookup_addr(h1) )
		{
		if ( h2 == 0.0.0.0 )
			{
			do_msg(out, n, line1, line2, line3, h1, h1name, h2, "");
			return;
			}

		when [out, n, h1, h2, line1, line2, line3, h1name] ( local h2name = lookup_addr(h2) )
			{
			do_msg(out, n, line1, line2, line3, h1, h1name, h2, h2name);
			return;
			}
		timeout 5secs
			{
			do_msg(out, n, line1, line2, line3, h1, h1name, h2, "(dns timeout)");
			return;
			}
		}

	timeout 5secs
		{
		if ( h2 == 0.0.0.0 )
			{
			do_msg(out, n, line1, line2, line3, h1,  "(dns timeout)", h2, "");
			return;
			}

		when [out, n, h1, h2, line1, line2, line3] ( local h2name_ = lookup_addr(h2) )
			{
			do_msg(out, n, line1, line2, line3, h1,  "(dns timeout)", h2, h2name_);
			return;
			}
		timeout 5secs
			{
			do_msg(out, n, line1, line2, line3, h1,  "(dns timeout)", h2, "(dns timeout)");
			return;
			}
		}
	}
