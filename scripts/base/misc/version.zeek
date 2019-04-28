##! Provide information about the currently running Bro version.
##! The most convenient way to access this are the Version::number
##! and Version::info constants.

@load base/frameworks/reporter
@load base/utils/strings

module Version;

export {
	## A type exactly describing a Bro version
	type VersionDescription: record {
		## Number representing the version which can be used for easy comparison.
		## The format of the number is ABBCC with A being the major version,
		## bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
		## As an example, Bro 2.4.1 results in the number 20401.
		version_number: count;
		## Major version number (e.g. 2 for 2.5)
		major: count;
		## Minor version number (e.g. 5 for 2.5)
		minor: count;
		## Patch version number (e.g. 0 for 2.5 or 1 for 2.4.1)
		patch: count;
		## Commit number for development versions, e.g. 12 for 2.4-12. 0 for non-development versions
		commit: count;
		## If set to true, the version is a beta build of Bro
		beta: bool;
		## If set to true, the version is a debug build
		debug: bool;
		## String representation of this version
		version_string: string;
	};

	## Parse a given version string.
	##
	## version_string: Bro version string.
	##
	## Returns: `VersionDescription` record.
	global parse: function(version_string: string): VersionDescription;

	## Test if the current running version of Bro is greater or equal to the given version
	## string.
	##
	## version_string: Version to check against the current running version.
	##
	## Returns: True if running version greater or equal to the given version.
	global at_least: function(version_string: string): bool;
}

function parse(version_string: string): VersionDescription
	{
	if ( /[[:digit:]]\.[[:digit:]][[:digit:]]?(\.[[:digit:]][[:digit:]]?)?(\-beta[[:digit:]]?)?(-[[:digit:]]+)?(\-debug)?/ != version_string )
		{
		Reporter::error(fmt("Version string %s cannot be parsed", version_string));
		return VersionDescription($version_number=0, $major=0, $minor=0, $patch=0, $commit=0, $beta=F, $debug=F, $version_string=version_string);
		}

	local components = split_string1(version_string, /\-/);
	local version_split = split_string(components[0], /\./);
	local major = to_count(version_split[0]);
	local minor = to_count(version_split[1]);
	local patchlevel = ( |version_split| > 2) ? to_count(version_split[2]) : 0;
	local version_number = major*10000+minor*100+patchlevel;
	local beta = /\-beta/ in version_string;
	local debug = /\-debug/ in version_string;
	local commit = 0;
	if ( |components| > 1 )
		{
		local commitpart = find_last(cat("-", components[1]), /\-[[:digit:]]+/);
		commit = ( |commitpart| > 0 ) ? to_count(sub_bytes(commitpart, 2, 999)) : 0;
		}

	return VersionDescription($version_number=version_number, $major=major, $minor=minor, $patch=patchlevel, $commit=commit, $beta=beta, $debug=debug, $version_string=version_string);
	}

export {
	## version number of the currently running version of Bro as a numeric representation.
	## The format of the number is ABBCC with A being the major version,
	## bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
	## As an example, Bro 2.4.1 results in the number 20401
	const number = Version::parse(bro_version())$version_number;

	## `VersionDescription` record pertaining to the currently running version of Bro.
	const info = Version::parse(bro_version());
}

function at_least(version_string: string): bool
	{
	return Version::number >= Version::parse(version_string)$version_number;
	}
