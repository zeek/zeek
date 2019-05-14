# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

const foo: table[string] of double &redef;

# full (re)initialization
redef foo = { ["nope"] = 37.0 };

# full (re)initialization, discards "nope" index
redef foo = { ["abc"] = 42.0 };

# add elements
redef foo += { ["def"] = -42.0, ["ghi"] = 7.0 };

# remove elements from LHS based on indices shared with RHS
redef foo -= { ["ghi"] = 0.0 };

# RHS can be a table value
redef foo += table(["cool"] = 5.0, ["neat"] = 1.0);

# Redef at a single index is allowed, same as += when RHS has overlapping index
redef foo["cool"] = 28.0;
redef foo["abc"] = 8.0;
redef foo += { ["def"] = 99.0 };

print foo;
