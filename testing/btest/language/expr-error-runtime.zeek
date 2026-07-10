# @TEST-DOC: Exercises the runtime (evaluation-time) error paths of src/Expr.cc (issue GH-2283). Each handler triggers one RuntimeError; the file framework's ZEEK_ALLOW_INIT_ERRORS lets Zeek report them all without a fatal exit.
#
# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# Arithmetic: division / modulo by zero.
event zeek_init() { local a = 1 / 0; }
event zeek_init() { local m = 5 % 0; }

# Shift: left-shifting a negative number is undefined.
event zeek_init() { local s = -1 << 2; }

# Vector arithmetic with operands of different sizes.
event zeek_init() { local x = vector(1, 2) + vector(1, 2, 3); }

# Indexing a vector with a boolean vector of a different size.
event zeek_init() { local v = vector(1, 2, 3); local b = vector(T, F); print v[b]; }

# Conditional expression whose condition and alternatives are vectors of different sizes.
event zeek_init() { local c = vector(T, F, T) ? vector(1, 2) : vector(3, 4); }

# Signed-int division / modulo by zero (distinct Fold branch from the count case).
event zeek_init() { local i: int = -6; local a = i / 0; }
event zeek_init() { local j: int = -6; local m = j % 0; }

# --- Additional runtime error paths (from the constructor/assign/operator regions) ---

# Accessing an unset &optional field.
type RVM: record { x: count &optional; };
event zeek_init() { local r = RVM(); print r$x; }

# A table literal whose key arity clashes with the declared index arity.
event zeek_init() { local t: table[count, count] of string = { [1] = "a" }; }

# An assignment used as a table-constructor value.
global asg_gx: count;
event zeek_init() { local t = table([1] = (asg_gx = 5)); }

# A list index containing an uninitialized (missing return) value.
function noret(): count { if ( F ) return 1; }
event zeek_init() { local t: table[count, count] of string; t[noret(), 2] = "x"; }

# Logical operation over vectors of different sizes.
event zeek_init() { local a: vector of bool = vector(T, F); local b: vector of bool = vector(T); local r = a && b; }

# Appending a record of the wrong type to a vector.
type VAR1: record { x: count; };
type VAR2: record { y: count; };
event zeek_init() { local v: vector of VAR1; local r2: VAR2 = [$y=1]; v += r2; }

# Using a declared-but-unset global function value.
global unset_func: function(): count;
event zeek_init() { local x = unset_func; }
