##! This script provides the framework for software version detection and
##! parsing but doesn't actually do any detection on it's own.  It relies on
##! other protocol specific scripts to parse out software from the protocols
##! that they analyze.  The entry point for providing new software detections
##! to this framework is through the :bro:id:`Software::found` function.

@load base/utils/directions-and-hosts
@load base/utils/numbers

module Software;

export {
	## The software logging stream identifier.
	redef enum Log::ID += { LOG };
	
	## Scripts detecting new types of software need to redef this enum to add
	## their own specific software types which would then be used when they 
	## create :bro:type:`Software::Info` records.
	type Type: enum {
		## A placeholder type for when the type of software is not known.
		UNKNOWN,
	};
	
	## A structure to represent the numeric version of software.
	type Version: record {
		## Major version number.
		major:  count  &optional;
		## Minor version number.
		minor:  count  &optional;
		## Minor subversion number.
		minor2: count  &optional;
		## Minor updates number.
		minor3: count  &optional;
		## Additional version string (e.g. "beta42").
		addl:   string &optional;
	} &log;
	
	## The record type that is used for representing and logging software.
	type Info: record {
		## The time at which the software was detected.
		ts:               time &log &optional;
		## The IP address detected running the software.
		host:             addr &log;
		## The port on which the software is running. Only sensible for
		## server software.
		host_p:           port &log &optional;
		## The type of software detected (e.g. :bro:enum:`HTTP::SERVER`).
		software_type:    Type &log &default=UNKNOWN;
		## Name of the software (e.g. Apache).
		name:             string &log &optional;
		## Version of the software.
		version:          Version &log &optional;
		## The full unparsed version string found because the version
		## parsing doesn't always work reliably in all cases and this
		## acts as a fallback in the logs.
		unparsed_version: string &log &optional;
		
		## This can indicate that this software being detected should
		## definitely be sent onward to the logging framework.  By 
		## default, only software that is "interesting" due to a change
		## in version or it being currently unknown is sent to the
		## logging framework.  This can be set to T to force the record
		## to be sent to the logging framework if some amount of this
		## tracking needs to happen in a specific way to the software.
		force_log:        bool &default=F;
	};
	
	## Hosts whose software should be detected and tracked.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	const asset_tracking = LOCAL_HOSTS &redef;
	
	## Other scripts should call this function when they detect software.
	## id: The connection id where the software was discovered.
	##
	## info: A record representing the software discovered.
	## 
	## Returns: T if the software was logged, F otherwise.
	global found: function(id: conn_id, info: Info): bool;
	
	## Compare two version records.
	## 
	## Returns:  -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
	##           If the numerical version numbers match, the *addl* string
	##           is compared lexicographically.
	global cmp_versions: function(v1: Version, v2: Version): int;
	
	## Type to represent a collection of :bro:type:`Software::Info` records.
	## It's indexed with the name of a piece of software such as "Firefox" 
	## and it yields a :bro:type:`Software::Info` record with more
	## information about the software.
	type SoftwareSet: table[string] of Info;
	
	## The set of software associated with an address.  Data expires from
	## this table after one day by default so that a detected piece of 
	## software will be logged once each day.
	global tracked: table[addr] of SoftwareSet 
		&create_expire=1day 
		&synchronized
		&redef;
	
	## This event can be handled to access the :bro:type:`Software::Info`
	## record as it is sent on to the logging framework.
	global log_software: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(Software::LOG, [$columns=Info, $ev=log_software]);
	}
	
type Description: record {
	name:             string;
	version:          Version;
	unparsed_version: string;
};

# Defining this here because of a circular dependency between two functions.
global parse_mozilla: function(unparsed_version: string): Description;

# Don't even try to understand this now, just make sure the tests are 
# working.
function parse(unparsed_version: string): Description
	{
	local software_name = "<parse error>";
	local v: Version;
	
	# Parse browser-alike versions separately
	if ( /^(Mozilla|Opera)\/[0-9]\./ in unparsed_version )
		{
		return parse_mozilla(unparsed_version);
		}
	else
		{
		# The regular expression should match the complete version number
		# and software name.
		local version_parts = split_n(unparsed_version, /\/?( [\(])?v?[0-9\-\._, ]{2,}/, T, 1);
		if ( 1 in version_parts )
			{
			if ( /^\(/ in version_parts[1] )
				software_name = strip(sub(version_parts[1], /[\(]/, ""));
			else
				software_name = strip(version_parts[1]);
			}
		if ( |version_parts| >= 2 )
			{
			# Remove the name/version separator if it's left at the beginning
			# of the version number from the previous split_all.
			local sv = strip(version_parts[2]);
			if ( /^[\/\-\._v\(]/ in sv )
				sv = strip(sub(version_parts[2], /^\(?[\/\-\._v\(]/, ""));
			local version_numbers = split_n(sv, /[\-\._,\[\(\{ ]/, F, 3);
			if ( 5 in version_numbers && version_numbers[5] != "" )
				v$addl = strip(version_numbers[5]);
			else if ( 3 in version_parts && version_parts[3] != "" &&
			          version_parts[3] != ")" )
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
			
			if ( 4 in version_numbers && version_numbers[4] != "" )
				v$minor3 = extract_count(version_numbers[4]);
			if ( 3 in version_numbers && version_numbers[3] != "" )
				v$minor2 = extract_count(version_numbers[3]);
			if ( 2 in version_numbers && version_numbers[2] != "" )
				v$minor = extract_count(version_numbers[2]);
			if ( 1 in version_numbers && version_numbers[1] != "" )
				v$major = extract_count(version_numbers[1]);
			}
		}
	
	return [$version=v, $unparsed_version=unparsed_version, $name=software_name];
	}


function parse_mozilla(unparsed_version: string): Description
	{
	local software_name = "<unknown browser>";
	local v: Version;
	local parts: table[count] of string;
	
	if ( /Opera [0-9\.]*$/ in unparsed_version )
		{
		software_name = "Opera";
		parts = split_all(unparsed_version, /Opera [0-9\.]*$/);
		if ( 2 in parts )
			v = parse(parts[2])$version;
		}
	else if ( / MSIE |Trident\// in unparsed_version )
		{
		software_name = "MSIE";
		if ( /Trident\/4\.0/ in unparsed_version )
			v = [$major=8,$minor=0];
		else if ( /Trident\/5\.0/ in unparsed_version )
			v = [$major=9,$minor=0];
		else if ( /Trident\/6\.0/ in unparsed_version )
			v = [$major=10,$minor=0];
		else if ( /Trident\/7\.0/ in unparsed_version )
			v = [$major=11,$minor=0];
		else
			{
			parts = split_all(unparsed_version, /MSIE [0-9]{1,2}\.*[0-9]*b?[0-9]*/);
			if ( 2 in parts )
				v = parse(parts[2])$version;
			}
		}
	else if ( /Version\/.*Safari\// in unparsed_version )
		{
		software_name = "Safari";
		parts = split_all(unparsed_version, /Version\/[0-9\.]*/);
		if ( 2 in parts )
			{
			v = parse(parts[2])$version;
			if ( / Mobile\/?.* Safari/ in unparsed_version )
				v$addl = "Mobile";
			}
		}
	else if ( /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/ in unparsed_version )
		{
		parts = split_all(unparsed_version, /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/);
		if ( 2 in parts )
			{
			local tmp_s = parse(parts[2]);
			software_name = tmp_s$name;
			v = tmp_s$version;
			}
		}
	else if ( /Chrome\/.*Safari\// in unparsed_version )
		{
		software_name = "Chrome";
		parts = split_all(unparsed_version, /Chrome\/[0-9\.]*/);
		if ( 2 in parts )
			v = parse(parts[2])$version;
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
				v = parse(parts[2])$version;
			else
				{
				parts = split_all(unparsed_version, /Opera Mini\/[0-9\.]*/);
				if ( 2 in parts )
					v = parse(parts[2])$version;
				}
			}
		else
			{
			software_name = "Opera";
			parts = split_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 2 in parts )
				v = parse(parts[2])$version;
			}
		}
	else if ( /AppleWebKit\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "Unspecified WebKit";
		parts = split_all(unparsed_version, /AppleWebKit\/[0-9\.]*/);
		if ( 2 in parts )
			v = parse(parts[2])$version;
		}

	return [$version=v, $unparsed_version=unparsed_version, $name=software_name];
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

	if ( v1?$minor3 && v2?$minor3 )
		{
		if ( v1$minor3 < v2$minor3 )
			return -1;
		if ( v1$minor3 > v2$minor3 )
			return 1;
		}
	else
		{
		if ( !v1?$minor3 && !v2?$minor3 )
			{ }
		else
			return v1?$minor3 ? 1 : -1;
		}

	if ( v1?$addl && v2?$addl )
		{
		return strcmp(v1$addl, v2$addl);
		}
	else
		{
		if ( !v1?$addl && !v2?$addl )
			return 0;
		else
			return v1?$addl ? 1 : -1;
		}

	# A catcher return that should never be reached...hopefully
	return 0;
	}

function software_endpoint_name(id: conn_id, host: addr): string
	{
	return fmt("%s %s", host, (host == id$orig_h ? "client" : "server"));
	}

# Convert a version into a string "a.b.c-x".
function software_fmt_version(v: Version): string
	{
	return fmt("%s%s%s%s%s", 
	           v?$major ? fmt("%d", v$major) : "0",
	           v?$minor ? fmt(".%d", v$minor) : "",
	           v?$minor2 ? fmt(".%d", v$minor2) : "",
	           v?$minor3 ? fmt(".%d", v$minor3) : "",
	           v?$addl ? fmt("-%s", v$addl) : "");
	}

# Convert a software into a string "name a.b.cx".
function software_fmt(i: Info): string
	{
	return fmt("%s %s", i$name, software_fmt_version(i$version));
	}

# Insert a mapping into the table
# Overides old entries for the same software and generates events if needed.
event register(id: conn_id, info: Info)
	{
	# Host already known?
	if ( info$host !in tracked )
		tracked[info$host] = table();

	local ts = tracked[info$host];
	# Software already registered for this host?  We don't want to endlessly
	# log the same thing.
	if ( info$name in ts )
		{
		local old = ts[info$name];
		
		# If the version hasn't changed, then we're just redetecting the
		# same thing, then we don't care.  This results in no extra logging.
		# But if the $force_log value is set then we'll continue.
		if ( ! info$force_log && cmp_versions(old$version, info$version) == 0 )
			return;
		}
	ts[info$name] = info;
	
	Log::write(Software::LOG, info);
	}

function found(id: conn_id, info: Info): bool
	{
	if ( info$force_log || addr_matches_host(info$host, asset_tracking) )
		{
		if ( !info?$ts ) 
			info$ts=network_time();
		
		if ( info?$version ) # we have a version number and don't have to parse. check if the name is also set...
			{
				if ( ! info?$name ) 
					{
					Reporter::error("Required field name not present in Software::found");
					return F;
					}
			}
		else  # no version present, we have to parse...
			{
			if ( !info?$unparsed_version ) 
				{
				Reporter::error("No unparsed version string present in Info record with version in Software::found");
				return F;
				}
			local sw = parse(info$unparsed_version);
			info$unparsed_version = sw$unparsed_version;
			info$name = sw$name;
			info$version = sw$version;
			}
		
		event register(id, info);
		return T;
		}
	else
		return F;
	}
