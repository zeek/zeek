# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Type inference for vector constructor comprised of disparate enum types
# should raise an error message about the types being incompatible.

type color: enum { Red, Green, Blue };
type number: enum { One, Two, Three, Four};
global v = vector(Red, Four, Blue);
