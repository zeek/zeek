# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global g: vector of int &variadic;

function foo(a: vector of string &variadic)
    {
    print "foo", a;
    }

function bar(a: vector of string &variadic, b: int)
    {
    print "bar", a;
    }

function baz(a: string &variadic)
    {
    print "baz", a;
    }

event zeek_init() &priority=-10
    {
    local a: vector of count &variadic;
    local b = vector("cool", "beans");

    foo("1", 2, "3");
    foo(b);
    }
