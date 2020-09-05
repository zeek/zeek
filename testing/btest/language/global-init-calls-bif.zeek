# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# This test isn't specifically testing the HLL cardinality functionality,
# rather that a global variable can be initialized using a BIF call.
# Also, it's particularly not a top-level BIF, but one defined in a subdir
# of the Zeek source tree (those are treated differently than top-level BIFs).

global my_cc = hll_cardinality_init(0.1, 0.999);

hll_cardinality_add(my_cc, 1);
hll_cardinality_add(my_cc, 2);
hll_cardinality_add(my_cc, 3);
print hll_cardinality_estimate(my_cc);
