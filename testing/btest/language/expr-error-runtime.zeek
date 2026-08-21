# @TEST-DOC: Exercises the runtime (evaluation-time) error paths of src/Expr.cc (issue GH-2283). Each handler triggers one RuntimeError; the file framework's ZEEK_ALLOW_INIT_ERRORS lets Zeek report them all without a fatal exit. Every erroring expression is print'd so that ZAM does not eliminate it as dead code, and only cases that raise the same runtime error under both the interpreter and ZAM are included here (the wording differs, hence the separate ZAM baseline).
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Arithmetic: division / modulo by zero (count). Operands are non-constant so the
# error is raised at evaluation time rather than folded away at compile time.
event zeek_init() { local z: count = 0; print 1 / z; }
event zeek_init() { local z: count = 0; print 5 % z; }

# Shift: left-shifting a negative number is undefined.
event zeek_init() { local neg: int = -1; local sh: count = 2; print neg << sh; }

# Vector arithmetic with operands of different sizes.
event zeek_init() { print vector(1, 2) + vector(1, 2, 3); }

# Indexing a vector with a boolean vector of a different size.
event zeek_init() { local v = vector(1, 2, 3); local b = vector(T, F); print v[b]; }

# Signed-int division / modulo by zero (distinct Fold branch from the count case).
event zeek_init() { local i: int = -6; local z: int = 0; print i / z; }
event zeek_init() { local j: int = -6; local z: int = 0; print j % z; }

# Accessing an unset &optional field.
type RVM: record { x: count &optional; };
event zeek_init() { local r = RVM(); print r$x; }

# Logical operation over vectors of different sizes.
event zeek_init() { local a: vector of bool = vector(T, F); local b: vector of bool = vector(T); print a && b; }

# Using a declared-but-unset global function value.
global unset_func: function(): count;
event zeek_init() { print unset_func; }

# Address masking with an out-of-range subnet prefix length (runtime MaskExpr fold).
event zeek_init() { local m: count = 40; print 1.2.3.4 / m; }
