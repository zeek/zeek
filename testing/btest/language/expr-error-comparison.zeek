# @TEST-DOC: Exercises the operand type-checking error paths of the comparison operators (EqExpr/RelExpr) in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

# Relational comparison of operands with different types.
function rel_type_mismatch() { local a = 1 < "s"; }

# Relational comparison that is not defined for the operand type.
function rel_illegal() { local a = T < F; }

# Equality comparison of operands with different types.
function eq_type_mismatch() { local a = 1 == "s"; }
