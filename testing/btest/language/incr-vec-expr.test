# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type rec: record {
    a: count;
    b: string;
    c: vector of count;
};

global vec: vector of count = vector(0,0,0);

global v: rec = [$a=0, $b="test", $c=vector(1,2,3)];

print vec;
print v;

++vec;

print vec;

++v$a;

print v;

++v$c;

print v;
