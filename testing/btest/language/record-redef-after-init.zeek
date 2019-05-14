# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type myrec: record {
    a: string;
};

const mr = myrec($a = "init") &redef;

redef mr = myrec($a = "redef");

# Many fields may help ensure out-of-bounds reference failures
redef record myrec += {
    d: string &optional;
    e: string &optional;
    f: string &optional;
    g: string &optional;
    h: string &optional;
    i: string &optional;
    j: string &optional;
    k: string &optional;
    l: string &optional;
    m: string &optional;
    n: string &optional;
    o: string &optional;
    p: string &optional;
    q: string &default="OPTQ";
};

print mr;                        # original 'myrec' type with updated a value
print myrec($a = "runtime");     # check we get new defaults

local mr2 = myrec($a = "local");
print mr2;

mr2 = mr;      # Copying should do the right thing
print mr2;

local mr3: myrec = mr; # Initializing should do the right thing
print mr3;

if ( mr?$q )    # the test that did not work properly
    {
    print mr$q; # accessed invalid memory location
    }
mr$p = "newp";  # Assignment updates mr as much as needed
print mr$p;
print mr;
print mr$q;
mr$q = "our value";
print mr$q;
print mr;
