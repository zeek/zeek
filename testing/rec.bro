# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record {
        a: count;
        b: count &optional;
};

redef record Foo += {
        c: count &default=42;
        d: count &optional;
};

global f: Foo = [$a=21];

print f;

