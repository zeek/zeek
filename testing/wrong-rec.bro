# @TEST-EXEC-FAIL: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

type Foo: record {
        a: count;
        b: count &optional;
};

redef record Foo += {
        c: count;
        d: string &optional;
};

