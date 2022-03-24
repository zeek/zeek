# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Tests for various mismatches in initializations.

global a: count = [3, 5];
global b [4, 6];
global c = 9;
global s1: set[double];
global s2: set[int];
global s3: set[count, count];
global t: table[addr] of bool;
global t2 = { [1, 3] = F, [2, 4, 6] = T };
global t3 = table( ["foo"] = 3, "bar" );
global v: vector of count;
global p: pattern;
global x = { };

function foo()
	{
	local subnets = { 1.2.3.4/24, 2.3.4.5/5 };
	local my_subnets: set[string, subnet];
	my_subnets = { ["foo", subnets] };
	}

c += { 2, 4 };
v -= { 3, 5 };

s1 += s2;
s1 -= s2;

s1 += { [3] = F };

s3 = { s2 };

p += 3;

t += { 1.2.3.4, F };

print a, b;
