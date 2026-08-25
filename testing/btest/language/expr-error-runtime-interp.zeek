# @TEST-DOC: Runtime (evaluation-time) error paths of src/Expr.cc (GH-2283) whose behavior differs under ZAM, so they are exercised under the interpreter only. Companion to expr-error-runtime.zeek.
#
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Conditional expression whose vector alternatives have different sizes.
# (Under ZAM this evaluates to a value instead of erroring, so it is interpreter-only.)
event zeek_init() { local c = vector(T, F, T); print c ? vector(1, 2) : vector(3, 4); }

# A list index containing an uninitialized (missing-return) value.
# (Under ZAM this aborts optimized execution, so it is interpreter-only.)
function noret(): count { if ( F ) return 1; }
event zeek_init() { local t: table[count, count] of string; t[noret(), 2] = "x"; }
