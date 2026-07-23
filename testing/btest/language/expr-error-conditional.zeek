# @TEST-DOC: Exercises the type-checking error paths of the conditional (ternary) operator (CondExpr) in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

# Non-boolean scalar condition.
function cond_non_bool() { local a = 1 ? 10 : 20; }

# Vector condition but scalar (non-vector) alternatives.
function cond_vector_scalar_alts() { local a = vector(T, F) ? 1 : 2; }
