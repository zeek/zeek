# @TEST-EXEC: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type Version: record {
        major:  count  &optional;
        minor:  count  &optional;
        minor2: count  &optional;
        addl:   string &optional;
};

type Info: record {
        name:    string;
        version: Version;
};

global matched_software: table[string] of Info = {
        ["OpenSSH_4.4"] = [$name="OpenSSH", $version=[$major=4,$minor=4]],
};

event bro_init()
        {
        for ( sw in matched_software )
                print matched_software[sw]$version;
        }
