# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# All various container constructors should work at both global and local scope.

global gt1: table[port] of count = table( [1/tcp] = 1, [2/tcp] = 2, [3/tcp] = 3 );
global gs1: set[port] = set( 1/tcp, 2/tcp, 3/tcp );
global gv1: vector of port = vector( 1/tcp, 2/tcp, 3/tcp, 1/tcp );

global gt2: table[port] of count = { [1/tcp] = 1, [2/tcp] = 2, [3/tcp] = 3 };
global gs2: set[port] = { 1/tcp, 2/tcp, 3/tcp };
global gv2: vector of port = { 1/tcp, 2/tcp, 3/tcp, 1/tcp };

local t1: table[port] of count = table( [1/tcp] = 1, [2/tcp] = 2, [3/tcp] = 3 );
local s1: set[port] = set( 1/tcp, 2/tcp, 3/tcp );
local v1: vector of port = vector( 1/tcp, 2/tcp, 3/tcp, 1/tcp );

local t2: table[port] of count = { [1/tcp] = 1, [2/tcp] = 2, [3/tcp] = 3 };
local s2: set[port] = { 1/tcp, 2/tcp, 3/tcp };
local v2: vector of port = { 1/tcp, 2/tcp, 3/tcp, 1/tcp };

print gt1;
print gt2;

print gs1;
print gs2;

print gv1;
print gv2;

print t1;
print t2;

print s1;
print s2;

print v1;
print v2;
