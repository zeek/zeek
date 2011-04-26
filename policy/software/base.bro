## This script provides the framework for software version detection and
## parsing, but doesn't actually do any detection on it's own.  It relys on
## other protocol specific scripts to parse out software from the protocol(s)
## that they analyze.  The entry point for providing new software detections
## to this framework is through the Software::found function.

@load functions
@load notice


module Software;

redef enum Notice::Type += { 
	## For certain softwares, a version changing may matter.  In that case, 
	## this notice will be generated.  Software that matters if the version
	## changes can be configured with the 
	## Software::interesting_version_changes variable.
	Software_Version_Change,
};

redef enum Log::ID += { SOFTWARE };

export {
	type Type: enum {
		UNKNOWN,
		OPERATING_SYSTEM,
		WEB_APPLICATION,
		FTP_SERVER,
		FTP_CLIENT,
		DATABASE_SERVER,
		## There are a number of ways to detect printers on the network.
		PRINTER,
	};

	type Version: record {
		major:  count  &optional;  ##< Major version number
		minor:  count  &optional;  ##< Minor version number
		minor2: count  &optional;  ##< Minor subversion number
		addl:   string &optional;  ##< Additional version string (e.g. "beta42")
	} &log;

	type Info: record {
		## The time at which the software was first detected.
		ts:               time &log;
		## The IP address detected running the software.
		host:             addr &log;
		## The type of software detected (e.g. WEB_SERVER)
		software_type:    Type &log &default=UNKNOWN;
		## Name of the software (e.g. Apache)
		name:             string &log;
		## Version of the software
		version:          Version &log;
		## The full unparsed version string found because the version parsing 
		## doesn't work 100% reliably and this acts as a fall back in the logs.
		unparsed_version: string &log &optional;
	};
	
	## The hosts whose software should be logged.
	## Choices are: LocalHosts, RemoteHosts, Enabled, Disabled
	const logging = Enabled &redef;

	## In case you are interested in more than logging just local assets
	## you can split the log file.
	#const split_log_file = F &redef;
	
	## Some software is more interesting when the version changes.  This is
	## a set of all software that should raise a notice when a different version
	## is seen.
	const interesting_version_changes: set[string] = {
		"SSH"
	} &redef;
	
	## Other scripts should call this function when they detect software.
	## @param unparsed_version: This is the full string from which the
	##                          Software::Info was extracted.
	## @return: T if the software was logged, F otherwise.
	global found: function(id: conn_id, info: Software::Info): bool;
	
	## This function can take many software version strings and parse them into 
	## a sensible Software::Version record.  There are still many cases where
	## scripts may have to have their own specific version parsing though.
	global parse: function(unparsed_version: string,
	                               host: addr,
	                               software_type: Type): Info;
	
	## Compare two versions.
	## @return:  Returns -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
	##           If the numerical version numbers match, the addl string
	##           is compared lexicographically.
	global cmp_versions: function(v1: Version, v2: Version): int;
	
	## Index is the name of the software.
	type SoftwareSet: table[string] of Info;
	# The set of software associated with an address.
	global tracked_software: table[addr] of SoftwareSet &create_expire=1day &synchronized;
	
	global log_software: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(SOFTWARE, [$columns=Info, $ev=log_software]);
	}
	
function parse_mozilla(unparsed_version: string, 
	                   host: addr, 
	                   software_type: Type): Info
	{
	local software_name = "<unknown browser>";
	local v: Version;
	local parts: table[count] of string;
	
	if ( /Opera [0-9\.]*$/ in unparsed_version )
		{
		software_name = "Opera";
		parts = split_all(unparsed_version, /Opera [0-9\.]*$/);
		if ( 2 in parts )
			v = parse(parts[2], host, software_type)$version;
		}
	else if ( /MSIE 7.*Trident\/4\.0/ in unparsed_version )
		{
		software_name = "MSIE"; 
		v = [$major=8,$minor=0];
		}
	else if ( / MSIE [0-9\.]*b?[0-9]*;/ in unparsed_version )
		{
		software_name = "MSIE";
		parts = split_all(unparsed_version, /MSIE [0-9\.]*b?[0-9]*/);
		if ( 2 in parts )
			v = parse(parts[2], host, software_type)$version;
		}
	else if ( /Version\/.*Safari\// in unparsed_version )
		{
		software_name = "Safari";
		parts = split_all(unparsed_version, /Version\/[0-9\.]*/);
		if ( 2 in parts )
			{
			v = parse(parts[2], host, software_type)$version;
			if ( / Mobile\/?.* Safari/ in unparsed_version )
				v$addl = "Mobile";
			}
		}
	else if ( /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/ in unparsed_version )
		{
		parts = split_all(unparsed_version, /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/);
		if ( 2 in parts )
			{
			local tmp_s = parse(parts[2], host, software_type);
			software_name = tmp_s$name;
			v = tmp_s$version;
			}
		}
	else if ( /Chrome\/.*Safari\// in unparsed_version )
		{
		software_name = "Chrome";
		parts = split_all(unparsed_version, /Chrome\/[0-9\.]*/);
		if ( 2 in parts )
			v = parse(parts[2], host, software_type)$version;
		}
	else if ( /^Opera\// in unparsed_version )
		{
		if ( /Opera M(ini|obi)\// in unparsed_version )
			{
			parts = split_all(unparsed_version, /Opera M(ini|obi)/);
			if ( 2 in parts )
				software_name = parts[2];
			parts = split_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 2 in parts )
				v = parse(parts[2], host, software_type)$version;
			else
				{
				parts = split_all(unparsed_version, /Opera Mini\/[0-9\.]*/);
				if ( 2 in parts )
					v = parse(parts[2], host, software_type)$version;
				}
			}
		else
			{
			software_name = "Opera";
			parts = split_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 2 in parts )
				v = parse(parts[2], host, software_type)$version;
			}
		}
	else if ( /AppleWebKit\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "Unspecified WebKit";
		parts = split_all(unparsed_version, /AppleWebKit\/[0-9\.]*/);
		if ( 2 in parts )
			v = parse(parts[2], host, software_type)$version;
		}

	return [$ts=network_time(), $host=host, $name=software_name, $version=v,
	        $software_type=software_type, $unparsed_version=unparsed_version];
	}

# Don't even try to understand this now, just make sure the tests are 
# working.
function parse(unparsed_version: string,
	           host: addr,
	           software_type: Type): Info
	{
	local software_name = "<parse error>";
	local v: Version;
	
	# Parse browser-alike versions separately
	if ( /^(Mozilla|Opera)\/[0-9]\./ in unparsed_version )
		{
		return parse_mozilla(unparsed_version, host, software_type);
		}
	else
		{
		# The regular expression should match the complete version number
		# and software name.
		local version_parts = split_n(unparsed_version, /\/?( [\(])?v?[0-9\-\._, ]{2,}/, T, 1);
		if ( 1 in version_parts )
			software_name = strip(version_parts[1]);
		if ( |version_parts| >= 2 )
			{
			# Remove the name/version separator if it's left at the beginning
			# of the version number from the previous split_all.
			local sv = strip(version_parts[2]);
			if ( /^[\/\-\._v\(]/ in sv )
			 	sv = strip(sub(version_parts[2], /^\(?[\/\-\._v]/, ""));
			local version_numbers = split_n(sv, /[\-\._,\[\(\{ ]/, F, 3);
			if ( 4 in version_numbers && version_numbers[4] != "" )
				v$addl = strip(version_numbers[4]);
			else if ( 3 in version_parts && version_parts[3] != "" )
				{
				if ( /^[[:blank:]]*\([a-zA-Z0-9\-\._[:blank:]]*\)/ in version_parts[3] )
					{
					v$addl = split_n(version_parts[3], /[\(\)]/, F, 2)[2];
					}
				else
					{
					local vp = split_n(version_parts[3], /[\-\._,;\[\]\(\)\{\} ]/, F, 3);
					if ( |vp| >= 1 && vp[1] != "" )
						{
						v$addl = strip(vp[1]);
						}
					else if ( |vp| >= 2 && vp[2] != "" )
						{
						v$addl = strip(vp[2]);
						}
					else if ( |vp| >= 3 && vp[3] != "" )
						{
						v$addl = strip(vp[3]);
						}
					else
						{
						v$addl = strip(version_parts[3]);
						}
						
					}
				}
		
			if ( |version_numbers| >= 3 && version_numbers[3] != "" )
				v$minor2 = to_count(version_numbers[3]);
			if ( |version_numbers| >= 2 && version_numbers[2] != "" )
				v$minor = to_count(version_numbers[2]);
			if ( |version_numbers| >= 1 && version_numbers[1] != "" )
				v$major = to_count(version_numbers[1]);
			}
		}
	return [$ts=network_time(), $host=host, $name=software_name,
	        $version=v, $unparsed_version=unparsed_version,
	        $software_type=software_type];
	}


function cmp_versions(v1: Version, v2: Version): int
	{
	if ( v1?$major && v2?$major )
		{
		if ( v1$major < v2$major )
			return -1;
		if ( v1$major > v2$major )
			return 1;
		}
	else
		{
		if ( !v1?$major && !v2?$major )
			{ }
		else
		return v1?$major ? 1 : -1;
		}
		
	if ( v1?$minor && v2?$minor )
		{
		if ( v1$minor < v2$minor )
			return -1;
		if ( v1$minor > v2$minor )
			return 1;
		}
	else
		{
		if ( !v1?$minor && !v2?$minor )
			{ }
		else
			return v1?$minor ? 1 : -1;
		}
		
	if ( v1?$minor2 && v2?$minor2 )
		{
		if ( v1$minor2 < v2$minor2 )
			return -1;
		if ( v1$minor2 > v2$minor2 )
			return 1;
		}
	else
		{
		if ( !v1?$minor2 && !v2?$minor2 )
			{ }
		else
			return v1?$minor2 ? 1 : -1;
		}

	if ( v1?$addl && v2?$addl )
		return strcmp(v1$addl, v2$addl);
	else
		{
		if ( !v1?$addl && !v2?$addl )
			return 0;
		else
			return v1?$addl ? 1 : -1;
		}
	}

function software_endpoint_name(id: conn_id, host: addr): string
	{
	return fmt("%s %s", host, (host == id$orig_h ? "client" : "server"));
	}

# Convert a version into a string "a.b.c-x".
function software_fmt_version(v: Version): string
	{
	return fmt("%d.%d.%d%s", 
	           v?$major ? v$major : 0,
	           v?$minor ? v$minor : 0,
	           v?$minor2 ? v$minor2 : 0,
	           v?$addl ? fmt("-%s", v$addl) : "");
	}

# Convert a software into a string "name a.b.cx".
function software_fmt(i: Info): string
	{
	return fmt("%s %s", i$name, software_fmt_version(i$version));
	}

# Insert a mapping into the table
# Overides old entries for the same software and generates events if needed.
event software_register(id: conn_id, info: Info)
	{
	# Host already known?
	if ( info$host !in tracked_software )
		tracked_software[info$host] = table();

	local ts = tracked_software[info$host];
	# Software already registered for this host?
	if ( info$name in ts )
		{
		local old = ts[info$name];
		
		# Is it a potentially interesting version change 
		# and is it a different version?
		if ( info$name in interesting_version_changes &&
		     cmp_versions(old$version, info$version) != 0 )
			{
			local msg = fmt("%.6f %s switched from %s to %s (%s)",
					network_time(), software_endpoint_name(id, info$host),
					software_fmt_version(old$version),
					software_fmt(info), info$software_type);
			NOTICE([$note=Software_Version_Change, $id=id,
			        $msg=msg, $sub=software_fmt(info)]);
			}
		else
			{
			# If the software is known to be on this host already and version
			# changes either aren't interesting or it's the same version as
			# already known, just return and don't log.
			return;
			}
		}
	
	Log::write(SOFTWARE, info);
	ts[info$name] = info;
	}

function found(id: conn_id, info: Info): bool
	{
	if ( addr_matches_hosts(info$host, logging) )
		{
		event software_register(id, info);
		return T;
		}
	else
		return F;
	}
