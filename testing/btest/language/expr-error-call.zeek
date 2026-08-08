# @TEST-DOC: Exercises the type-checking error paths of function/event/hook calls in src/Expr.cc (issue GH-2283).
#
# @TEST-EXEC-FAIL: zeek -b %INPUT 2>err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

hook a_hook() { }
function two_arg_func(a: count, b: count) { }
event an_event() { }
global a_declared_event: event(c: count, d: count);
function a_yielding_func(): count { return 1; }

# Calling a non-function value.
function call_non_function() { local x: count = 5; x(); }

# Calling a hook directly instead of via the hook operator.
function call_hook_directly() { a_hook(); }

# Wrong number of arguments to a function.
function call_arg_mismatch() { two_arg_func(1); }

# Calling an event as if it were a value-returning function.
function call_event_in_expr() { an_event(); }

# 'event' on a name that isn't an event.
function event_not_an_event() { event totally_made_up_name_xyz(); }

# Wrong arguments in an event invocation.
function event_arg_mismatch() { event a_declared_event(1); }

# Invoking a plain function via the 'event' keyword.
function func_invoked_as_event() { event a_yielding_func(); }

# Lambda that references an outer identifier without a [] capture list.
function lambda_uncaptured_outer() { local x = 5; local g = function() { print x; }; }
