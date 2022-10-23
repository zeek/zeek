# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

# Demo policy for the sizeof operator "|x|".
# ------------------------------------------
#
# This script creates various types and values and shows the result of the
# sizeof operator on these values.
#
# For any types not covered in this script, the sizeof operator's semantics
# are not defined and its application returns a count of 0. At the moment
# the only type where this should happen is string patterns.

type example_enum: enum { ENUM1, ENUM2, ENUM3 };

type example_record: record {
	i: int &optional;
	j: int &optional;
	k: int &optional;
};

global a:  addr = 1.2.3.4;
global a6: addr = [::1];
global b:  bool = T;
global c:  count = 10;
global d:  double = -1.23;
global f:  file = open("sizeof_demo.log");
global i:  int = -10;
global iv: interval = -5sec;
global p:  port = 80/tcp;
global r:  example_record = [ $i = +10 ];
global si: set[int];
global s:  string = "Hello";
global sn: subnet = 192.168.0.0/24;
global t:  table[string] of string;
global ti: time = current_time();
global v:  vector of string;

# Additional initialization
#
print f, "12345678901234567890";

add si[1];
add si[10];
add si[100];

t["foo"] = "Hello";
t["bar"] = "World";

v[0] = "Hello";
v[4] = "World";

# Print out the sizes of the various vals:
#-----------------------------------------

# Size of addr: returns number of bits required to represent the address
# which is 32 for IPv4 or 128 for IPv6
print fmt("IPv4 Address %s: %d", a, |a|);
print fmt("IPv6 Address %s: %d", a6, |a6|);

# Size of boolean: returns 1 or 0.
print fmt("Boolean %s: %d", b, |b|);

# Size of count: identity.
print fmt("Count %s: %d", c, |c|);

# Integer literals that lack a "+" or "-" modifier are of the unsigned "count"
# type, so this wraps to a very large number.  It may be more intuitive if it
# were to coerce to a signed integer, but it can also be more favorable to
# simply have consistent behavior across arbitrary arithmetic expressions even
# if that may result in occasional, unintended overflow/wrapping.
print fmt("Expr: %d", |5 - 9|);
# Same arithmetic on signed integers is likely what's originally intended.
print fmt("Signed Expr: %d", |+5 - +9|);

# Size of double: returns absolute value.
print fmt("Double %s: %f", d, |d|);

# Size of enum: returns numeric value of enum constant.
print fmt("Enum %s: %d", ENUM3, |ENUM3|);

# Size of file: returns current file size.
# Note that this is a double so that file sizes >> 4GB
# can be expressed.
print fmt("File %f", |f|);

# Size of function: returns number of arguments.
print fmt("Function add_interface: %d", |add_interface|);

# Size of integer: returns absolute value.
print fmt("Integer %s: %d", i, |i|);

# Size of interval: returns double representation of the interval
print fmt("Interval %s: %f", iv, |iv|);

# Size of port: returns port number as a count.
print fmt("Port %s: %d", p, |p|);

# Size of record: returns number of fields (assigned + unassigned)
print fmt("Record %s: %d", r, |r|);

# Size of set: returns number of elements in set.
# Don't print the set, as its order depends on the seeding of the hash
# function, and it's not worth the trouble to normalize it.
print fmt("Set: %d", |si|);

# Size of string: returns string length.
print fmt("String '%s': %d", s, |s|);

# Size of subnet: returns size of net as a double 
# (so that 2^32 can be expressed too).
print fmt("Subnet %s: %f", sn, |sn|);

# Size of table: returns number of elements in table
print fmt("Table %d", |t|);

# Size of time: returns double representation of the time
# print fmt("Time %s: %f", ti, |ti|);

# Size of vector: returns largest assigned index.
# Note that this is not the number of assigned values.
# The following prints "5":
#
print fmt("Vector %s: %d", v, |v|);

close(f);
