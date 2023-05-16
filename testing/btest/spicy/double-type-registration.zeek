# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -L . -o a.hlto a.spicy
# @TEST-EXEC: spicyz -L . -o b.hlto b.spicy
# @TEST-EXEC: zeek a.hlto b.hlto
#
# @TEST-EXEC: spicyz -o a.hlto a.spicy common.spicy
# @TEST-EXEC: spicyz -o b.hlto b.spicy common.spicy
# @TEST-EXEC: zeek a.hlto b.hlto
#
# @TEST-DOC: Regression test for #177.

# @TEST-START-FILE common.spicy
module common;

public type E = enum {
	X,
	Y,
};
# @TEST-END-FILE

# @TEST-START-FILE a.spicy
module a;

import common;
global x: common::E;
# @TEST-END-FILE

# @TEST-START-FILE b.spicy
module b;

import common;
global x: common::E;
# @TEST-END-FILE
