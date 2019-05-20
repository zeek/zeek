# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type Foo: record {
	x: count &default=0;
};

global foo: table[count] of Foo = {} &default=[];

# returns the &default value as usual
print(foo[0]$x);
print(foo[1]$x);

# these are essentially no-ops since a copy of the &default value is returned
# by the lookup
foo[0]$x = 0;
foo[1]$x = 1;

# the &default value isn't modified
print(foo[0]$x);
print(foo[1]$x);

# table membership isn't modified
print(foo);
