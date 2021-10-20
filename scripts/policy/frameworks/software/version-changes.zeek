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
		## :zeek:id:`Software::interesting_version_changes` variable.
		Software_Version_Change,
	};

	## Some software is more interesting when the version changes and this
	## is a set of all software that should raise a notice when a different
	## version is seen on a host.
	option interesting_version_changes: set[string] = {};
}

event Software::version_change(old: Software::Info, new: Software::Info)
	{
	if ( old$name !in interesting_version_changes )
		return;

	local msg = fmt("%.6f %s '%s' version changed from %s to %s",
	                network_time(), old$software_type, old$name,
	                software_fmt_version(old$version),
                	software_fmt_version(new$version));

	NOTICE([$note=Software_Version_Change, $src=new$host,
	        $msg=msg, $sub=software_fmt(new)]);
	}
