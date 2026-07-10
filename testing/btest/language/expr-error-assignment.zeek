# @TEST-DOC: Exercises the type-checking error paths of assignment, lvalue, and initialization in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

type AName: count;
type Color: enum { Red, Green };
type AR: record { a: count; b: count; };
const a_const = 5;
option an_option = 5;
global a_global: count;
function a_void_func() { }

# Assigning to something that is not an lvalue.
function assign_to_non_lvalue() { local a = 1; (a + a) = 2; }

# Assigning to a type name.
function assign_to_type_name() { AName = 5; }

# Assigning to a const.
function assign_to_const() { a_const = 6; }

# Assigning to an option outside of the option-setting API.
function assign_to_option() { an_option = 6; }

# Assigning a void (no-yield) call result.
function assign_void_value() { local x: count; x = a_void_func(); }

# Assigning a bare number to an enum-typed variable.
function assign_bad_enum() { local e: Color; e = 5; }

# Assigning a value of the wrong type.
function assign_type_clash() { local s: string; s = 5; }

# Initializer whose first operand is not a list.
function init_first_operand_not_list() { local x = (a_global = 5); }

# Initializing a record with a bare list.
function init_bad_record() { local r: AR; r = [1, 2]; }

# List-assignment target with a non-identifier element.
function assign_list_non_identifier() { local a: count; [a, 1 + 1] = [1, 2]; }
