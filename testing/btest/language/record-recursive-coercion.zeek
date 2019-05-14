# @TEST-EXEC: zeek -b %INPUT >output
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

type Foo: record {
        i: interval &default=1hr;
        s: string &optional;
};

type FooContainer: record {
        c: count;
        f: Foo &optional;
};

function foo_func(fc: FooContainer)
        {
        print fc;
        }

event zeek_init()
        {
        for ( sw in matched_software )
                print matched_software[sw]$version;
        foo_func([$c=1, $f=[$i=2hrs]]);
        }
