##! Provide information about the currently running Zeek version.
##! The most convenient way to access this are the Version::number
##! and Version::info constants.

@load base/frameworks/reporter
@load base/utils/strings

module Version;

export {
	## A type exactly describing a Zeek version
	type VersionDescription: record {
		## Number representing the version which can be used for easy comparison.
		## The format of the number is ABBCC with A being the major version,
		## bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
		## As an example, Zeek 2.4.1 results in the number 20401.
		version_number: count;
		## Major version number (e.g. 2 for 2.5)
		major: count;
		## Minor version number (e.g. 5 for 2.5)
		minor: count;
		## Patch version number (e.g. 0 for 2.5 or 1 for 2.4.1)
		patch: count;
		## Commit number for development versions, Versions prior to 3.0.0,
		## like "2.4-12", use a post-release commit number (12 commits
		## after the 2.4 release).  Versions after 3.0.0, like
		## "3.1.0-dev.37", use a pre-release commit number (37 commits
		## into the development cycle for 3.1.0).  For non-development version
		## this number will be zero.
		commit: count;
		## If set to true, the version is a beta build of Zeek.  These versions
		## may start like "2.6-beta" or "3.0.0-rc" (the "rc" form started
		## being used for 3.0.0 and later).
		beta: bool;
		## If set to true, the version is a debug build
		debug: bool;
		## Local version portion of the version string
		localversion: string;
		## String representation of this version
		version_string: string;
	};

	## Parse a given version string.
	##
	## version_string: Zeek version string.
	##
	## Returns: `VersionDescription` record.
	global parse: function(version_string: string): VersionDescription;

	## Test if the current running version of Zeek is greater or equal to the given version
	## string.
	##
	## version_string: Version to check against the current running version.
	##
	## Returns: True if running version greater or equal to the given version.
	global at_least: function(version_string: string): bool;
}

function parse(version_string: string): VersionDescription
	{
	if ( /[0-9]+\.[0-9]+(\.[0-9]+)?(-(beta|rc|dev)[0-9]*)?(\.[0-9]+)?(-[a-zA-Z0-9_\.]+)?(-debug)?/ != version_string )
		{
		Reporter::error(fmt("Version string %s cannot be parsed", version_string));
		return VersionDescription($version_number=0, $major=0, $minor=0, $patch=0, $commit=0, $beta=F, $debug=F, $localversion="", $version_string=version_string);
		}

	local beta = /-(beta|rc)/ in version_string;
	local debug = /-debug/ in version_string;
	local patchlevel = 0;
	local commit = 0;
	local vs = version_string;
	local localversion = "";

	local parts = split_string1(vs, /\./);
	local major = to_count(parts[0]);

	vs = lstrip(vs, "1234567890");
	vs = lstrip(vs, ".");

	parts = split_string1(vs, /\.|-/);
	local minor = to_count(parts[0]);

	vs = lstrip(vs, "1234567890");

	if ( |vs| > 0 )
		{
		# More than just X.Y
		if ( vs[0] == "." )
			{
			vs = lstrip(vs, ".");
			parts = split_string1(vs, /\.|-/);
			patchlevel = to_count(parts[0]);
			vs = lstrip(vs, "1234567890");
			}

		vs = gsub(vs, /-debug$/, "");
		vs = gsub(vs, /-(beta|rc|dev)[0-9]*/, "");
		localversion = find_last(vs, /-[a-zA-Z0-9_\.]+$/);
                if ( localversion != "" )
			{
			# Remove leadig dash from localversion
			localversion = lstrip(localversion, "-");
			# Drop the local version piece from the version string
			vs = gsub(vs, /-[a-zA-Z0-9_\.]+$/, "");
			}

		# A .X possibly remaining
		vs = lstrip(vs, ".");

		if ( |vs| > 0 )
			commit = to_count(vs);
		}

	local version_number = major * 10000 + minor * 100 + patchlevel;

	return VersionDescription($version_number=version_number, $major=major,
	                          $minor=minor, $patch=patchlevel, $commit=commit,
	                          $beta=beta, $debug=debug,
				  $localversion=localversion,
	                          $version_string=version_string);
	}

export {
	## `VersionDescription` record pertaining to the currently running version of Zeek.
	const info = Version::parse(zeek_version());

	## version number of the currently running version of Zeek as a numeric representation.
	## The format of the number is ABBCC with A being the major version,
	## bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
	## As an example, Zeek 2.4.1 results in the number 20401
	const number = info$version_number;
}

function at_least(version_string: string): bool
	{
	return Version::number >= Version::parse(version_string)$version_number;
	}
