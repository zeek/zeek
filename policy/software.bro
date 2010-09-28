# $Id: software.bro 4907 2007-09-23 23:44:07Z vern $
#
# Keeps track of the software running on hosts.

@load site
@load weird

# Operational use of software.bro on a busy network can result in huge
# data files.  By default creating a log file is turned off.
global log_software = F &redef;

# If true, then logging is confined to just software versions of local hosts.
global only_report_local = T &redef;

global software_file = open_log_file("software");

# Invoked whenever we discover new software for a host (but not for a new
# version of previously found software).
global software_new: event(c: connection, host: addr, s: software,
				descr: string);

# Invoked whenever we discover a new version of previously discovered
# software.
global software_version_change: event(c: connection, host: addr, s: software,
	old_version: software_version, descr: string);

# Index is the name of the software.
type software_set: table[string] of software;

# You may or may not want to define a timeout for this.
global software_table: table[addr] of software_set;

# Some software can be installed twice on the same server
# with different major numbers.
global software_ident_by_major: set[string] = {
	"PHP",
	"WebSTAR",
} &redef;

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

# Convert a version into a string "a.b.c-x".
function software_fmt_version(v: software_version): string
	{
	return fmt("%s%s%s%s",
			v$major >= 0 ? fmt("%d", v$major) : "",
			v$minor >= 0 ? fmt(".%d", v$minor) : "",
			v$minor2 >= 0 ? fmt(".%d", v$minor2) : "",
			v$addl != "" ? fmt("-%s", v$addl) : "");
	}

# Convert a software into a string "name a.b.cx".
function software_fmt(s: software): string
	{
	return fmt("%s %s", s$name, software_fmt_version(s$version));
	}

# Insert a mapping into the table
# Overides old entries for the same software and generates events if needed.
### FIXME: Do we need a software_unregister() as well?
function software_register(c: connection, host: addr, s: software,
				descr: string)
	{
	# Host already known?
	if ( host !in software_table )
		software_table[host] = set();

	# If a software can be installed more than once on a host
	# (with a different major version), we identify it by "<name>-<major>"
	if ( s$name in software_ident_by_major && s$version$major >= 0 )
		s$name = fmt("%s-%d", s$name, s$version$major);

	local soft_set = software_table[host];

	# Software already registered for this host?
	if ( s$name in soft_set )
		{
		# Is it a different version?
		local old = soft_set[s$name];
		if ( software_cmp_version(old$version, s$version) != 0 )
			event software_version_change(c, host, s, old$version,
							descr);
		}
	else
		event software_new(c, host, s, descr);

	soft_set[s$name] = s;
	}

event software_version_found(c: connection, host: addr, s: software,
				descr: string)
	{
	if ( ! only_report_local || is_local_addr(host) )
		software_register(c, host, s, descr);
	}

function software_endpoint_name(c: connection, host: addr): string
	{
	return fmt("%s %s", host,
			host == c$id$orig_h ? "client" : "server");
	}

event software_parse_error(c: connection, host: addr, descr: string)
	{
	if ( ! only_report_local || is_local_addr(host) )
		{
		# Here we need a little hack, since software_file is
		# not always there.
		local msg = fmt("%.6f %s: can't parse '%s'", network_time(),
				software_endpoint_name(c, host), descr);

		if ( log_software )
			print software_file, msg;
		else
			print Weird::weird_file, msg;
		}
	}

event software_new(c: connection, host: addr, s: software, descr: string)
	{
	if ( log_software )
		{
		print software_file, fmt("%.6f %s uses %s (%s)", network_time(),
					software_endpoint_name(c, host),
					software_fmt(s), descr);
		}
	}

event software_version_change(c: connection, host: addr, s: software,
				old_version: software_version, descr: string)
	{
	if ( log_software )
		{
		local msg = fmt("%.6f %s switched from %s to %s (%s)",
				network_time(), software_endpoint_name(c, host),
				software_fmt_version(old_version),
				software_fmt(s), descr);

		print software_file, msg;
		}
	}

event software_unparsed_version_found(c: connection, host: addr, str: string)
	{
	if ( log_software )
		{
		print software_file, fmt("%.6f %s: [%s]", network_time(),
					software_endpoint_name(c, host), str);
		}
	}
