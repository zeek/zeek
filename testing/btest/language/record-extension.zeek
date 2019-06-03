# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type Foo: record {
        a: count;
        b: count &optional;
        myset: set[count] &default=set();
};

redef record Foo += {
        c: count &default=42;
        d: string &optional;
        anotherset: set[count] &default=set();
};

global f1: Foo = [$a=21];
global f2: Foo = [$a=21, $d="XXX"];

print f1;
print f2;

