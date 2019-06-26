# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

type test_enum1: enum { ONE };

module TEST;

type test_enum2: enum { TWO };

print ONE;
print fmt("%s", ONE);


print TWO;
print fmt("%s", TWO);
