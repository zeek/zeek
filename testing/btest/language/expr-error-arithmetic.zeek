# @TEST-DOC: Exercises the operand type-checking error paths of the unary and binary arithmetic operators in src/Expr.cc (issue GH-2283). Each function triggers one error; Zeek reports them all in a single analysis pass.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

# --- Unary operators ---

# ComplementExpr: requires a "count" operand.
function complement_non_count() { local a = ~"s"; }

# NotExpr: requires an integral or boolean operand.
function not_non_integral() { local a = ! 1.5; }

# PosExpr: requires an integral or double operand.
function pos_non_numeric() { local a = +"s"; }

# NegExpr: requires an integral or double operand.
function neg_non_numeric() { local a = -"s"; }

# --- Binary arithmetic operators ---

# AddExpr: mixing string with a non-string, non-arithmetic operand.
function add_string_and_bool() { local a = "s" + T; }

# SubExpr: requires arithmetic operands.
function sub_non_arith() { local a = "s" - 1; }

# TimesExpr: requires arithmetic operands.
function times_non_arith() { local a = "s" * 1; }

# DivideExpr: requires arithmetic operands.
function divide_non_arith() { local a = "s" / 1; }

# ModExpr: requires integral operands.
function mod_non_integral() { local a = "s" % 1; }

# BinaryExpr: cannot mix a vector operand with a scalar operand.
function mix_vector_and_scalar() { local v = vector(1, 2, 3); local a = v + 1; }

# AddToExpr (+=): appending a non-arithmetic element to an arithmetic vector.
function append_non_arith_to_vector() { local v = vector(1, 2); v += "s"; }
