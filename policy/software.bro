@load global-ext
@load weird

module Software;

redef enum Notice += { 
	Software_Version_Change,
};

export {
	redef enum Log::ID += { SOFTWARE };
	type Log: record {
		ts: time;
		host: addr;
		software: string;
		version:  string;
		description: string;
		
	};
	
	type Version: record {
		major: count;    # Major version number
		minor: count;    # Minor version number
		minor2: count;   # Minor subversion number
		addl: string;    # Additional version string (e.g. "beta42")
	};
	
	type Type: enum = {
		WEB_SERVER, WEB_BROWSER,
		MAIL_SERVER, MAIL_CLIENT,
		FTP_SERVER, FTP_CLIENT,
		
	};

	type Software: record {
		name: string;             # Unique name of a software, e.g., "OS"
		type: Type;       # 
		version: Version;
	};
	
	
	## The hosts whose software should be logged.
	## Choices are: LocalHosts, RemoteHosts, Enabled, Disabled
	#const logging = Enabled &redef;

	## In case you are interested in more than logging just local assets
	## you can split the log file.
	#const split_log_file = F &redef;

	# Some software can be installed twice on the same server
	# with different major numbers.
	const identify_by_major: set[string] = {
		"PHP",
		"WebSTAR",
	} &redef;
	
	## Some software is more interesting when the version changes.  This is
	## a set of all software that should raise a notice when a different version
	## is seen.
	const interesting_version_changes: set[string] = {
		"SSH"
	} &redef;
	
	# Raise this event from other scripts when software is discovered.
	# This event is actually defined internally in Bro.
	#global software_version_found: event(c: connection, host: addr, s: software, descr: string);	
	
	global found: event(c: connection, host: addr, s: software, full_);
	
	# Index is the name of the software.
	type SoftwareSet: table[string] of software;
	# The set of software associated with an address.
	global host_software: table[addr] of SoftwareSet &create_expire=1day &synchronized;
}

event bro_init()
	{
	Log::create_stream("SOFTWARE", "Software::Log");
	Log::add_default_filter("SOFTWARE");
	}

# Compare two versions.
#   Returns -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
#   If the numerical version numbers match, the addl string
#   is compared lexicographically.
function software_cmp_version(v1: software_version, v2: software_version): int
	{
	if ( v1$major < v2$major )
		return -1;
	if ( v1$major > v2$major )
		return 1;

	if ( v1$minor < v2$minor )
		return -1;
	if ( v1$minor > v2$minor )
		return 1;

	if ( v1$minor2 < v2$minor2 )
		return -1;
	if ( v1$minor2 > v2$minor2 )
		return 1;

	return strcmp(v1$addl, v2$addl);
	}
	
function software_endpoint_name(c: connection, host: addr): string
	{
	return fmt("%s %s", host, (host == c$id$orig_h ? "client" : "server"));
	}

# Convert a version into a string "a.b.c-x".
function software_fmt_version(v: software_version): string
	{
	return fmt("%s%s%s%s",
	           v$major >= 0  ? fmt("%d", v$major)   : "",
	           v$minor >= 0  ? fmt(".%d", v$minor)  : "",
	           v$minor2 >= 0 ? fmt(".%d", v$minor2) : "",
	           v$addl != ""  ? fmt("-%s", v$addl)   : "");
	}

# Convert a software into a string "name a.b.cx".
function software_fmt(s: software): string
	{
	return fmt("%s %s", s$name, software_fmt_version(s$version));
	}
	
event software_new(c: connection, host: addr, s: software, descr: string)
	{
	if ( addr_matches_hosts(host, logging) )
		{
		local log = LOG::get_file_by_addr("software-ext", host, F);
		print log, cat_sep("\t", "\\N", 
		                   network_time(), host,
		                   s$name, software_fmt_version(s$version), descr);
		}
	}

# Insert a mapping into the table
# Overides old entries for the same software and generates events if needed.
event software_register(c: connection, host: addr, s: software, descr: string)
	{
	# Host already known?
	if ( host !in host_software )
		host_software[host] = table();

	# If a software can be installed more than once on a host
	# (with a different major version), we identify it by "<name>-<major>"
	if ( s$name in identify_by_major && s$version$major >= 0 )
		s$name = fmt("%s-%d", s$name, s$version$major);

	local hs = host_software[host];
	# Software already registered for this host?
	if ( s$name in hs )
		{
		local old = hs[s$name];
		
		# Is it a potentially interesting version change 
		# and is it a different version?
		if ( s$name in interesting_version_changes &&
		     software_cmp_version(old$version, s$version) != 0 )
			{
			local msg = fmt("%.6f %s switched from %s to %s (%s)",
					network_time(), software_endpoint_name(c, host),
					software_fmt_version(old$version),
					software_fmt(s), descr);
			NOTICE([$note=Software_Version_Change, $conn=c,
			        $msg=msg, $sub=software_fmt(s)]);
			}
		}
	else
		{
		event software_new(c, host, s, descr);
		}

	hs[s$name] = s;
	}


########################################
# Below are internally defined events. #
########################################
	
event software_version_found(c: connection, host: addr, s: software, descr: string)
	{
	if ( addr_matches_hosts(host, logging) )
		event software_register(c, host, s, descr);
	}

event software_parse_error(c: connection, host: addr, descr: string)
	{
	if ( addr_matches_hosts(host, logging) )
		{
		# Here we need a little hack, since software_file is
		# not always there.
		local msg = fmt("%.6f %s: can't parse '%s'", network_time(),
				software_endpoint_name(c, host), descr);

		print Weird::weird_file, msg;
		}
	}

# I'm not going to handle this at the moment.  It doesn't seem terribly useful.
#event software_unparsed_version_found(c: connection, host: addr, str: string)
#	{
#	if ( addr_matches_hosts(host, logging) )
#		{
#		print Weird::weird_file, fmt("%.6f %s: [%s]", network_time(),
#				software_endpoint_name(c, host), str);
#		}
#	}
