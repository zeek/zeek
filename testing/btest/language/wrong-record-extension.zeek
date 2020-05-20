# @TEST-EXEC-FAIL: zeek -b %INPUT  >output.tmp 2>&1 
# @TEST-EXEC: sed 's#^.*:##g' <output.tmp >output
# @TEST-EXEC: btest-diff output

type Foo: record {
        a: count;
        b: count &optional;
};

redef record Foo += {
        c: count;
        d: string &optional;
};

