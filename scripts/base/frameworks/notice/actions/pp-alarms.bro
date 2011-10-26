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

        ## If an address from one of these networks is involved in alarm, we mark
	## the entry with a quote symbol (i.e., ">"). Many mailers highlight such
	## lines in some way.
	global flag_nets: set[subnet] &redef;


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
	return T;
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
	
	#system(fmt("/bin/cat %s | %s -t -oi && /bin/rm %s",
	#	   pp_alarms_name, sendmail, pp_alarms_name));

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

	if ( ACTION_LOG !in n$actions )
		return;

	if ( ! pp_alarms_open )
		pp_open();

	pretty_print_alarm(pp_alarms, n);
	}

function do_msg(out: file, n: Info, line1: string, line2: string, line3: string, host: addr, name: string)
	{
	if ( host != 0.0.0.0 ) 
		{
		local country = "";
		if ( n?$remote_location && n$remote_location?$country_code  )
			country = fmt(" (%s)", n$remote_location$country_code);

		name = fmt(" %s = %s%s", host, name, country);
		}
	
	
	line1 = cat(line1, name);
	
	print out, line1;
	print out, line2;
	if ( line3 != "" )
		print out, line3;
	}

# Default pretty-printer.
function pretty_print_alarm(out: file, n: Info)
	{
	local pdescr = "";

@if ( Cluster::is_enabled() )	
	pdescr = "local";
	
	if ( n?$src_peer )
		pdescr = n$src_peer?$descr ? n$src_peer$descr : fmt("%s", n$src_peer$host);
	
	pdescr = fmt("<%s> ", pdescr);
@endif	

	local msg = fmt( "%s%s%s", pdescr, n$msg, n?$sub ? cat(" ", n$sub) : "");

	local orig = 0.0.0.0;
	local resp = 0.0.0.0;
	local host = 0.0.0.0;

	if ( n?$src )
		orig = host = n$src;

	if ( n?$id )
		{
		orig = n$id$orig_h;
		resp = n$id$resp_h;
		}

	if ( host == 0.0.0.0 )
		host = orig; 

	local flag = (orig in flag_nets || resp in flag_nets);
	
	local location = "";

	if ( host != 0.0.0.0 )
		location =  Site::is_local_addr(host) ? "(L)" : "(R)";

	local line1 = fmt(">%s %D %s %s", (flag ? ">" : " "), network_time(), n$note, location);
	local line2 = fmt("   %s", msg);   
	local line3 = ""; # Could use later.

	if ( host == 0.0.0.0 )
		{
		do_msg(out, n, line1, line2, line3, 0.0.0.0, "");
		return;
		}
	
	when ( local name = lookup_addr(host) )
		{
		do_msg(out, n, line1, line2, line3, host, name);
		}
	timeout 5secs
		{
		do_msg(out, n, line1, line2, line3, host, "(dns timeout)");
		}
	}
	
