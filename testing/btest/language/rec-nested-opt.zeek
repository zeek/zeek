# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type Version: record {
        major:  count &optional;    ##< Major version number
        minor:  count &optional;    ##< Minor version number
        addl:   string &optional;  ##< Additional version string (e.g. "beta42")
} &log;

type Info: record {
	name: string;
	version: Version;
	host: addr;
	ts: time;
};


# Important thing to note here is that $minor2 is not include in the $version field.
global matched_software: table[string] of Info = {
        ["Wget/1.9+cvs-stable (Red Hat modified)"] =
                [$name="Wget", $version=[$major=1,$minor=9,$addl="+cvs"], $host=0.0.0.0, $ts=network_time()],
};

print matched_software;
