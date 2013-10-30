##! Provides the possibility to define software names that are interesting to
##! watch for changes.  A notice is generated if software versions change on a
##! host.

@load base/frameworks/notice
@load base/frameworks/software

module Software;

export {
	redef enum Notice::Type += { 
		## For certain software, a version changing may matter.  In that
		## case, this notice will be generated.  Software that matters
		## if the version changes can be configured with the
		## :bro:id:`Software::interesting_version_changes` variable.
		Software_Version_Change,
	};
	
	## Some software is more interesting when the version changes and this
	## is a set of all software that should raise a notice when a different
	## version is seen on a host.
	const interesting_version_changes: set[string] = { } &redef;
}

event log_software(rec: Info)
	{
	local ts = tracked[rec$host];
	
	if ( rec$name in ts )
		{
		local old = ts[rec$name];
	
		# Is it a potentially interesting version change?
		if ( rec$name in interesting_version_changes )
			{
			local msg = fmt("%.6f %s switched from %s to %s (%s)",
					network_time(), rec$software_type,
					software_fmt_version(old$version),
					software_fmt(rec), rec$software_type);
			NOTICE([$note=Software_Version_Change, $src=rec$host,
			        $msg=msg, $sub=software_fmt(rec)]);
			}
		}
	}
