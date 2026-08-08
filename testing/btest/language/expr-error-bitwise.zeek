# @TEST-DOC: Exercises the operand type-checking error paths of the bitwise, shift, and logical operators in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

# BoolExpr (&&, ||): require boolean operands.
function and_non_bool() { local a = "s" && T; }
function or_non_bool()  { local a = "s" || T; }

# BitExpr (&): requires "count" or compatible "set" operands.
function bitand_non_integral() { local a = 1.5 & 2; }

# Shift (<<): requires integral operands.
function shift_non_integral_rhs() { local a = 1 << "s"; }

# Shift (<<): cannot mix a vector and a scalar operand.
function shift_vector_scalar_mix() { local v = vector(1, 2); local a = v << 1; }
