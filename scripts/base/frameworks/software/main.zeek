##! This script provides the framework for software version detection and
##! parsing but doesn't actually do any detection on it's own.  It relies on
##! other protocol specific scripts to parse out software from the protocols
##! that they analyze.  The entry point for providing new software detections
##! to this framework is through the :zeek:id:`Software::found` function.

@load base/utils/directions-and-hosts
@load base/utils/numbers
@load base/frameworks/cluster

module Software;

export {
	## The software logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Scripts detecting new types of software need to redef this enum to add
	## their own specific software types which would then be used when they
	## create :zeek:type:`Software::Info` records.
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
		## The type of software detected (e.g. :zeek:enum:`HTTP::SERVER`).
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
	option asset_tracking = LOCAL_HOSTS;

	## The framework maintains per-node caches that map unparsed version
	## strings to :zeek:type:`Software::Version` instances. This is its
	## expiration interval.
	const parse_cache_interval = 65secs &redef;

	## The framework maintains a redundancy cache in each worker that
	## deduplicates their version reporting in :zeek:see:`Software::found`.
	## This is its expiration interval. Setting to 0secs disables this cache.
	const found_cache_interval = 10mins &redef;

	## For each software, each proxy maintains a per-host deduplication
	## cache of known versions that refreshes daily. This setting caps the
	## size of each of these caches. Exceeding the cap leads to a reset of
	## the cache, and to redundant software.log writes. 0 disables the cap.
	const max_software_cache_size = 20 &redef;

	## Other scripts should call this function when they detect software.
	##
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

	## Sometimes software will expose itself on the network with
	## slight naming variations.  This table provides a mechanism
	## for a piece of software to be renamed to a single name
	## even if it exposes itself with an alternate name.  The
	## yielded string is the name that will be logged and generally
	## used for everything.
	global alternate_names: table[string] of string = {
		["Flash Player"] = "Flash",
	} &default=function(a: string): string { return a; };


	## Type to represent a set of software versions of the same name,
	## tracking the most recent version explicitly.
	type Set: record {
		## Set of version strings, unparsed when available (for full
		## detail) or based on a :zeek:see:`Software::Version` record.
		versions: set[string];
		## The most recent software info record for this set.
		last: Info &optional;
	};

	## Type to represent a collection of :zeek:type:`Software::Info` records.
	## It's indexed with the name of a piece of software such as "Firefox"
	## and it yields a :zeek:type:`Software::Set` with specific versions
	## of the software.
	type SoftwareSets: table[string] of Set;

	## The set of software associated with an address.  Data expires from
	## this table after one day by default so that a detected piece of
	## software will be logged once each day.  In a cluster, this table is
	## uniformly distributed among proxy nodes.
	global tracked_software: table[addr] of SoftwareSets &create_expire=1day;

	type SoftwareSet: table[string] of Info &deprecated="Remove in v9.1. Use SoftwareSets instead.";
@pragma push ignore-deprecations
	global tracked: table[addr] of SoftwareSet &create_expire=1day &deprecated="Remove in v9.1. Unused. Use tracked_software instead.";
@pragma pop ignore-deprecations

	## This event can be handled to access the :zeek:type:`Software::Info`
	## record as it is sent on to the logging framework.
	global log_software: event(rec: Info);

	## This event can be handled to access software information whenever it's
	## version is found to have changed.
	global version_change: event(old: Info, new: Info);

	## This event is raised when software is about to be registered for
	## tracking in :zeek:see:`Software::tracked_software`.
	global register: event(info: Info);
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
	if ( /^(Mozilla|Opera)\/[0-9]+\./ in unparsed_version )
		{
		return parse_mozilla(unparsed_version);
		}
	else if ( /A\/[0-9\.]*\/Google\/Pixel/ in unparsed_version )
		{
		software_name = "Android (Google Pixel)";
		local parts = split_string_all(unparsed_version, /\//);
		if ( 2 in parts )
			{
			local vs = parts[2];

			if ( "." in vs )
				v = parse(vs)$version;
			else
				v = Version($major=extract_count(vs));

			return Description($version=v, $unparsed_version=unparsed_version, $name=software_name);
			}
		}
	else
		{
		# The regular expression should match the complete version number
		# and software name.
		local clean_unparsed_version = gsub(unparsed_version, /\\x/, "%");
		clean_unparsed_version = unescape_URI(clean_unparsed_version);
		local version_parts = split_string_n(clean_unparsed_version, /([\/\-_]|( [\(v]+))?[0-9\-\._, ]{2,}/, T, 1);
		if ( 0 in version_parts )
			{
			# Remove any bits of junk at end of first part.
			if ( /([\/\-_]|( [\(v]+))$/ in version_parts[0] )
				version_parts[0] = strip(sub(version_parts[0], /([\/\-_]|( [\(v]+))/, ""));

			if ( /^\(/ in version_parts[0] )
				software_name = strip(sub(version_parts[0], /\(/, ""));
			else
				software_name = strip(version_parts[0]);
			}
		if ( |version_parts| >= 2 )
			{
			# Remove the name/version separator if it's left at the beginning
			# of the version number from the previous split_all.
			local sv = strip(version_parts[1]);
			if ( /^[\/\-\._v\(]/ in sv )
				sv = strip(sub(sv, /^[\/\-\._v\(]/, ""));

			local version_numbers = split_string_n(sv, /[\-\._,\[\(\{ ]/, F, 3);
			if ( 4 in version_numbers && version_numbers[4] != "" )
				v$addl = strip(version_numbers[4]);
			else if ( 2 in version_parts && version_parts[2] != "" &&
			          version_parts[2] != ")" )
				{
				if ( /^[[:blank:]]*\([a-zA-Z0-9\-\._[:blank:]]*\)/ in version_parts[2] )
					{
					v$addl = split_string_n(version_parts[2], /[\(\)]/, F, 2)[1];
					}
				else
					{
					local vp = split_string_n(version_parts[2], /[\-\._,;\[\]\(\)\{\} ]/, F, 3);
					if ( |vp| >= 1 && vp[0] != "" )
						{
						v$addl = strip(vp[0]);
						}
					else if ( |vp| >= 2 && vp[1] != "" )
						{
						v$addl = strip(vp[1]);
						}
					else if ( |vp| >= 3 && vp[2] != "" )
						{
						v$addl = strip(vp[2]);
						}
					else
						{
						v$addl = strip(version_parts[2]);
						}

					}
				}

			if ( 3 in version_numbers && version_numbers[3] != "" )
				v$minor3 = extract_count(version_numbers[3]);
			if ( 2 in version_numbers && version_numbers[2] != "" )
				v$minor2 = extract_count(version_numbers[2]);
			if ( 1 in version_numbers && version_numbers[1] != "" )
				v$minor = extract_count(version_numbers[1]);
			if ( 0 in version_numbers && version_numbers[0] != "" )
				v$major = extract_count(version_numbers[0]);
			}
		}

	return Description($version=v, $unparsed_version=unparsed_version, $name=alternate_names[software_name]);
	}

# A cache for the proxies that stores the result of parsing unparsed_version.
global parse_cache: table[string] of Description;
# A suppression cache for the workers to prevent sending the same information to the proxies multiple times.
global found_cache: set[Info];

# Call parse, but cache results in the parse_cache table
function parse_with_cache(unparsed_version: string): Description
	{
	if (unparsed_version in parse_cache)
		return parse_cache[unparsed_version];

	local res = parse(unparsed_version);
	parse_cache[unparsed_version] = res;
	return res;
	}

function parse_mozilla(unparsed_version: string): Description
	{
	local software_name = "<unknown browser>";
	local v: Version;
	local parts: string_vec;

	if ( /Opera [0-9\.]*$/ in unparsed_version )
		{
		software_name = "Opera";
		parts = split_string_all(unparsed_version, /Opera [0-9\.]*$/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( / MSIE |Trident\// in unparsed_version )
		{
		software_name = "MSIE";
		if ( /Trident\/4\.0/ in unparsed_version )
			v = Version($major=8,$minor=0);
		else if ( /Trident\/5\.0/ in unparsed_version )
			v = Version($major=9,$minor=0);
		else if ( /Trident\/6\.0/ in unparsed_version )
			v = Version($major=10,$minor=0);
		else if ( /Trident\/7\.0/ in unparsed_version )
			v = Version($major=11,$minor=0);
		else
			{
			parts = split_string_all(unparsed_version, /MSIE [0-9]{1,2}\.*[0-9]*b?[0-9]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			}
		}
	else if ( /Edge\// in unparsed_version )
		{
		software_name="Edge";
		parts = split_string_all(unparsed_version, /Edge\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /Version\/.*Safari\// in unparsed_version )
		{
		software_name = "Safari";
		parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
		if ( 1 in parts )
			{
			v = parse(parts[1])$version;
			if ( / Mobile\/?.* Safari/ in unparsed_version )
				v$addl = "Mobile";
			}
		}
	else if ( /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/ in unparsed_version )
		{
		parts = split_string_all(unparsed_version, /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/);
		if ( 1 in parts )
			{
			local tmp_s = parse(parts[1]);
			software_name = tmp_s$name;
			v = tmp_s$version;
			}
		}
	else if ( /Chrome\/.*Safari\// in unparsed_version )
		{
		software_name = "Chrome";
		parts = split_string_all(unparsed_version, /Chrome\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /^Opera\// in unparsed_version )
		{
		if ( /Opera M(ini|obi)\// in unparsed_version )
			{
			parts = split_string_all(unparsed_version, /Opera M(ini|obi)/);
			if ( 1 in parts )
				software_name = parts[1];
			parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			else
				{
				parts = split_string_all(unparsed_version, /Opera Mini\/[0-9\.]*/);
				if ( 1 in parts )
					v = parse(parts[1])$version;
				}
			}
		else
			{
			software_name = "Opera";
			parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			}
		}
	else if ( /Flash%20Player/ in unparsed_version )
		{
		software_name = "Flash";
		parts = split_string_all(unparsed_version, /[\/ ]/);
		if ( 2 in parts )
			v = parse(parts[2])$version;
		}

	else if ( /AdobeAIR\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "AdobeAIR";
		parts = split_string_all(unparsed_version, /AdobeAIR\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /AppleWebKit\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "Unspecified WebKit";
		parts = split_string_all(unparsed_version, /AppleWebKit\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( / Java\/[0-9]\./ in unparsed_version )
		{
		software_name = "Java";
		parts = split_string_all(unparsed_version, /Java\/[0-9\._]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}

	return Description($version=v, $unparsed_version=unparsed_version, $name=software_name);
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

# Convert a version into a string "a.b.c-x".  Marked "&is_used" because
# while the base scripts don't call it, the optional policy/ scripts do.
function software_fmt_version(v: Version): string &is_used
	{
	return fmt("%s%s%s%s%s",
	           v?$major ? fmt("%d", v$major) : "0",
	           v?$minor ? fmt(".%d", v$minor) : "",
	           v?$minor2 ? fmt(".%d", v$minor2) : "",
	           v?$minor3 ? fmt(".%d", v$minor3) : "",
	           v?$addl ? fmt("-%s", v$addl) : "");
	}

# Like software_fmt_version(), but preferably returns the unparsed
# version string when available. Falls back to the parsed one otherwise,
# and the empty string in the (unlikely) case that both fail.
function software_fmt_unparsed_version(i: Info): string
	{
	if ( i?$unparsed_version )
		return i$unparsed_version;
	if ( i?$version )
		return software_fmt_version(i$version);

	# This isn't supposed to happen because Software::found() already checks
	# for the presence of at least once of those fields. We do this just for
	# robustness.
	Reporter::error("Software::Info record has neither version nor unparsed_version");
	return "<unknown>";
	}

# Convert a software into a string "name a.b.cx".  Same as above re "&is_used".
function software_fmt(i: Info): string &is_used
	{
	return fmt("%s %s", i$name, software_fmt_version(i$version));
	}

function software_in_sets(info: Info, ss: SoftwareSets): bool
	{
	if ( info$name in ss && software_fmt_unparsed_version(info) in ss[info$name]$versions )
		return T;

	return F;
	}

# Parse unparsed_version if needed before raising register event
# This is used to maintain the behavior of the exported Software::register
# event that expects a pre-parsed 'name' field.
event Software::new(info: Info)
	{
	if ( ! info?$version )
		{
		local sw = parse_with_cache(info$unparsed_version);
		info$unparsed_version = sw$unparsed_version;
		info$name = sw$name;
		info$version = sw$version;
		}

	event Software::register(info);
	}

event Software::register(info: Info)
	{
	local ss: SoftwareSets;

	if ( info$host in tracked_software )
		ss = tracked_software[info$host];
	else
		ss = tracked_software[info$host] = SoftwareSets();

	# Software already registered for this host?  We don't want to endlessly
	# log the same thing, unless we're explicitly asked to do so.
	if ( software_in_sets(info, ss) )
		{
		if ( ! info$force_log )
			return;
		}
	else
		{
		if ( info$name !in ss )
			ss[info$name] = Set();
		else
			event Software::version_change(ss[info$name]$last, info);

		add ss[info$name]$versions[software_fmt_unparsed_version(info)];
		ss[info$name]$last = info;

		# If the set just got too large, simply start over with the
		# newest version. We currently lack a good way to track a set
		# and its newest/oldest members.
		if ( max_software_cache_size > 0 && |ss[info$name]$versions| > max_software_cache_size )
			ss[info$name]$versions = {software_fmt_unparsed_version(info)};
		}

	Log::write(Software::LOG, info);
	}

function found(id: conn_id, info: Info): bool
	{
	if ( ! info$force_log && ! addr_matches_host(info$host, asset_tracking) )
		return F;

	# This assumes that callers do not fill in info$ts, none of the current callers do.
	if ( found_cache_interval > 0secs )
		{
		if ( info in found_cache )
			return T;
		add found_cache[info];
		}

	if ( ! info?$ts )
		info$ts = network_time();

	if ( info?$version )
		{
		if ( ! info?$name )
			{
			Reporter::error("Required field name not present in Software::found");
			return F;
			}
		}
	else if ( ! info?$unparsed_version )
		{
		Reporter::error("No unparsed version string present in Info record with version in Software::found");
		return F;
		}

	@if ( Cluster::is_enabled() )
		Cluster::publish_hrw(Cluster::proxy_pool, info$host, Software::new, info);
	@else
		event Software::new(info);
	@endif

	return T;
	}

event zeek_init() &priority=5
	{
	parse_cache = table() &read_expire=parse_cache_interval;

	if ( found_cache_interval > 0secs )
		found_cache = set() &create_expire=found_cache_interval;

	Log::create_stream(Software::LOG, Log::Stream($columns=Info, $ev=log_software, $path="software", $policy=log_policy));
	}
