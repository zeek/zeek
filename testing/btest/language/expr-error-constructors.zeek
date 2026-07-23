# @TEST-DOC: Exercises the type-checking error paths of the record/table/set/vector constructors in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

type CR: record { a: count; };

# RecordConstructorExpr: a bare positional value where a $field assignment is required.
function record_bad_type() { local x = CR(5); }

# RecordConstructorExpr: a $field assigned a value of the wrong type.
function record_bad_field_type() { local x = CR($a = "x"); }

# RecordConstructorExpr: assignment to a field the record doesn't have.
function record_no_such_field() { local x = CR($b = 5); }

# A table constructor used where a set is expected.
function table_ctor_non_table_context() { local s: set[count] = { [1] = 2 }; }

# table() whose key is not bracketed.
function table_cannot_determine_type() { local x = table([$a=1] = 2); }

# table() given bare values instead of key/yield pairs.
function table_values_not_a_table() { local x = table(1, 2); }

# A bare value mixed into a table constructor.
function table_illegal_element() { local t: table[count] of count = { [1] = 2, 3 }; }

# A table constructor index that is not a list.
function table_index_not_a_list() { local t: table[count] of count = { [$a=1] = 2 }; }

# Table constructor index type inconsistent with the declared index type.
function table_inconsistent_index() { local t: table[count] of count = { ["x"] = 2 }; }

# Table constructor value type inconsistent with the declared yield type.
function table_inconsistent_value() { local t: table[count] of count = { [1] = "x" }; }

# set() assigned where a differently-typed table is expected.
function set_bad_type() { local t: table[count] of string; t = set(1, 2); }

# set() given key/yield pairs instead of bare index values.
function set_values_not_a_set() { local x = set([1] = 2); }

# A set element whose type is inconsistent with the declared index type.
function set_inconsistent_type() { local s: set[count] = { "x" }; }

# A scalar where a multi-index set expects a list of indices.
function set_not_a_list_of_indices() { local s: set[count, count] = { 1 }; }

# A multi-index set element with inconsistent index types.
function set_inconsistent_types() { local s: set[count, count] = { ["x", 1] }; }

# A vector constructor with elements of inconsistent types.
function vector_inconsistent_types() { local v: vector of count = [1, "x"]; }
