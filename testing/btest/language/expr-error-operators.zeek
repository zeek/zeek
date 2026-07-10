# @TEST-DOC: Exercises the remaining operator type-checking error paths in src/Expr.cc (issue GH-2283): compound assignment (+=/-=), interval arithmetic, address masking, bit/shift/pattern ops, set/record comparison, vector conditionals, and schedule.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

type OpRec: record { x: count; };
event op_event() { }

# -= with a constructor list on a vector.
function remove_ctor_list_vector() { local v: vector of count = vector(1, 2); v -= { 1, 2 }; }

# += with a constructor list on a non-aggregate.
function add_ctor_list_bad() { local a: addr = 1.2.3.4; a += { 1.2.3.5 }; }

# ++ on a non-integral operand.
function incr_non_integral() { local s: string = "a"; ++s; }

# Arithmetic addition with a non-arithmetic operand.
function add_non_arith() { local x = 1.2.3.4 + 1; }

# 'add' on something that is not a set element.
function illegal_add() { local c: count = 5; add c; }

# 'delete' on something that is not a table/set element.
function illegal_delete() { local c: count = 5; delete c; }

# += between tables with mismatched yield types.
function addto_table_mismatch() { local t1: table[count] of string; local t2: table[count] of count; t1 += t2; }

# += on a pattern with a non-pattern operand.
function addto_pattern_bad() { local p: pattern = /a/; p += "x"; }

# += on an address (neither two arithmetic nor two string operands).
function addto_addr() { local a: addr = 1.2.3.4; a += 1; }

# -= on an address (neither two arithmetic operands).
function removefrom_addr() { local a: addr = 1.2.3.4; a -= 1; }

# Subtracting sets with incompatible index types.
function sub_incompatible_sets() { local s1: set[count]; local s2: set[string]; local r = s1 - s2; }

# -= between tables with mismatched yield types.
function removefrom_table_mismatch() { local t1: table[count] of string; local t2: table[count] of count; t1 -= t2; }

# Multiplying two intervals.
function mult_interval() { local x = 1sec * 1sec; }

# Dividing an interval by a non-arithmetic operand.
function div_interval() { local x = 1sec / "a"; }

# '/' address masking with a non-count/int RHS.
function mask_bad_rhs() { local a: addr = 1.2.3.4; local r = a / a; }

# Shift with a non-count right operand.
function shift_bad_rhs() { local x = 1 << -1; }

# Mixing a pattern and a non-pattern in a bit operation.
function bit_pattern_mix() { local p: pattern = /a/; local r = p | "x"; }

# '^' applied to patterns.
function xor_patterns() { local r = /a/ ^ /b/; }

# Comparing sets with incompatible index types.
function eq_incompatible_sets() { local s1: set[count]; local s2: set[string]; local r = s1 == s2; }

# Equality comparison of a type that doesn't support it.
function eq_illegal() { local a: OpRec; local b: OpRec; local r = a == b; }

# Comparing a string vector with a pattern vector.
function eq_string_pattern_vectors() { local vp: vector of pattern = vector(/a/); local vs: vector of string = vector("a"); local r = vp == vs; }

# Vector conditional whose alternatives clash (both-vector path in CondExpr).
function cond_vector_clash() { local cond: vector of bool = vector(T, F); local a: vector of string = vector("a", "b"); local b: vector of string = vector("c", "d"); local r = cond ? a : b; }

# Conditional whose alternatives are of different types.
function cond_scalar_clash() { local r = T ? "a" : 5; }

# schedule with a non-time/interval delay.
function schedule_bad_delay() { schedule 5 { op_event() }; }

# '|' (union) on sets with incompatible index types.
function bitor_incompatible_sets() { local s1: set[count]; local s2: set[string]; local r = s1 | s2; }

# Subset comparison of sets with incompatible index types.
function subset_incompatible_sets() { local s1: set[count]; local s2: set[string]; local r = s1 < s2; }
