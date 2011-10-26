#! Notice extension that mails out a pretty-printed version of alarm.log
#! in regular intervals, formatted for better human readability. If activated,
#! that replaces the default summary mail having the raw log output.

module Notice;

export {
	## Activate pretty-printed alarm summaries.
	const pretty_print_alarms = T &redef;

	## Address to send the pretty-printed reports to. Default if not set is
	## :bro:id:`Notice::mail_dest`.
	const mail_dest_pretty_printed = "" &redef;

	## Function that renders a single alarm. Can be overidden.
	global pretty_print_alarm: function(out: file, n: Info) &redef;
}

# We maintain an old-style file recording the pretty-printed alarms.
const  pp_alarms_name = "alarm-mail.txt";
global pp_alarms: file;
global pp_alarms_open: bool = F;

# Returns True if pretty-printed alarm summaries are activated.
function want_pp() : bool
	{
	return (pretty_print_alarms && ! reading_traces()
		&& (mail_dest != "" || mail_dest_pretty_printed != ""));
	}

# Opens and intializes the output file.
function pp_open()
	{
	if ( pp_alarms_open )
		return;

	pp_alarms_open = T;
	pp_alarms = open(pp_alarms_name);

	local dest = mail_dest_pretty_printed != "" ? mail_dest_pretty_printed
		: mail_dest;
	
	local headers = email_headers("Alarm summary", dest);
	write_file(pp_alarms, headers + "\n");
	}

# Closes and mails out the current output file.
function pp_send()
	{
	if ( ! pp_alarms_open )
		return;

	write_file(pp_alarms, "\n\n--\n[Automatically generated]\n\n");
	close(pp_alarms);
	
	system(fmt("/bin/cat %s | %s -t -oi && /bin/rm %s",
		   pp_alarms_name, sendmail, pp_alarms_name));

	pp_alarms_open = F;
	}

# Postprocessor function that triggers the email.
function pp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( want_pp() )
		pp_send();
	
	return T;
	}

event bro_init()
	{
	if ( ! want_pp() )
		return;

	# This replaces the standard non-pretty-printing filter.
	Log::add_filter(Notice::ALARM_LOG,
			[$name="alarm-mail", $writer=Log::WRITER_NONE,
			 $interv=Log::default_rotation_interval,
			 $postprocessor=pp_postprocessor]);
	}

event notice(n: Notice::Info) &priority=-5
	{
	if ( ! want_pp() )
		return;
	
	if ( ACTION_ALARM !in n$actions )
		return;

	if ( ! pp_alarms_open )
		pp_open();

	pretty_print_alarm(pp_alarms, n);
	}

# Default pretty-printer.
function pretty_print_alarm(out: file, n: Info)
	{
	print out, n;
	}




