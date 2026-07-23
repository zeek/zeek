# @TEST-DOC: Exercises the type-checking error paths of field access ($) and indexing/slicing/membership in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

type FR: record { a: count; };

# Field access on a non-record value.
function field_on_non_record() { local x = 5; print x$foo; }

# Access to a field the record doesn't have.
function field_no_such_field() { local r: FR; print r$nope; }

# Slice notation on a type that doesn't support slicing.
function slice_unsupported() { local t: table[count] of string; print t[1:2]; }

# Multi-element index on a string.
function string_index_invalid() { local s = "abc"; print s[1,2]; }

# Assigning through a string index.
function string_index_assign() { local s = "abc"; s[0] = "x"; }

# Membership test against a non-index type.
function membership_non_index() { local a = 5; local b = 5; print a in b; }

# Pattern membership against a non-string/set/table value.
function pattern_membership_bad() { local p = /foo/; local x = 5; print p in x; }

# HasFieldExpr (?$) on a non-record value.
function hasfield_non_record() { local x = 5; local b = x ?$ foo; }

# HasFieldExpr (?$) for a field the record doesn't have.
function hasfield_no_field() { local r: FR; local b = r ?$ nope; }
