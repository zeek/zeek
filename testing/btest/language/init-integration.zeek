# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

# A bunch of tests for the unification of global initializations and
# =/+=/-= expressions.

# This is used just to pull in an example that works for globals, to make
# sure it works for locals.
@load base/frameworks/cluster

# This first covers the bug that motivated the unification.

type Key: record {
	k0: string;
	k1: string &optional;
};

global init_key = [$k0="x"];

# This used to crash or produce an ASAN error.
global state: table[Key] of count = {
	[init_key] = 5,
};

global my_subnets = { 1.2.3.4/19, 5.6.7.8/21 };

event zeek_init()
	{
	print(fmt("init_key in state: %d", init_key in state));

	# Check that the local version works.
	local init_key2 = [$k0="y"];
	local state2: table[Key] of count = { [init_key2] = 6 };
	print(fmt("init_key2 in state2: %d", init_key2 in state2));

	# Now checking that a complex initialization that works for
	# globals also works for locals.
	local cluster_nodes = {
		["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=3/tcp],
		["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=5/udp, $manager="manager-1"],
		["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=7/tcp, $manager="manager-1"],
};

	cluster_nodes += { ["worker-3"] = [$node_type=Cluster::WORKER, $ip=1.2.3.4, $p=9/udp] };
	print cluster_nodes;

	cluster_nodes -= { ["worker-2"] = [$node_type=Cluster::MANAGER, $ip=0.0.0.0, $p=11/tcp] };
	print cluster_nodes;

	# Similar, but without type inference.
	local cluster_nodes2: table[string] of Cluster::Node;
	cluster_nodes2 = { ["worker-4"] = [$node_type=Cluster::WORKER, $ip=2.3.4.5, $p=13/udp] };

	local cluster_nodes3: table[string] of Cluster::Node = {
		["worker-5"] = [$node_type=Cluster::WORKER, $ip=3.4.5.6, $p=15/tcp]
	};

	print cluster_nodes2;
	cluster_nodes2 += cluster_nodes3;
	print cluster_nodes2;
	cluster_nodes2 -= cluster_nodes3;
	cluster_nodes2 += table(["worker-6"] = Cluster::Node($node_type=Cluster::WORKER, $ip=4.5.6.7, $p=17/udp));
	print cluster_nodes2;

	# Test automatic type conversions.
	local s: set[double, int];
	s += { [3, 4] };
	print s;
	s -= { [3, 3] };
	print s;
	s -= { [3, 4] };
	print s;
	# Note, the following correctly generates a type-mismatch error
	# if we use set([9, 4]) since that's a set[count, count], not
	# a set[double, int].
	s += set([9.0, +4]);
	print s;

	# Similar, for tables.
	local t: table[double, double] of double;
	t += { [3, 4] = 5 };
	print t;
	t -= { [3, 3] = 9 };
	print t;
	t -= { [3, 4] = 7 };
	print t;

	# Test use of sets for expansion.  my_subnets needs to be a global,
	# because expansion happens at compile-time.
	local x: set[string, subnet];
	x += { [["foo", "bar"], my_subnets] };
	print x;

	# Test adding to patterns dynamically.
	local p = /foo/;
	p += /bar/;
	print p;

	# Tests for vectors.
	local v: vector of count;
	local v2 = vector(20, 21, 22, 23);
	v = { 1, 3, 5 };
	v += 9;
	v += { 2, 4, 6 };
	v += v2;
	print v;

	local v3: vector of vector of count;
	local v4 = vector(vector(80, 81), vector(90, 91, 92));
	v3 += { vector(3,2,1), vector(1,2,3) };
	v3 += v2;
	v3 += v4;
	print v3;
	}
