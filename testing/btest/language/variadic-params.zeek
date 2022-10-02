# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

### functions

global foo_func: function(a: vector of any &variadic);

# &variadic transfer from the declaration automatically
function foo_func(a: vector of any)
    {
    print "foo_func", a;
    }

function bar_func(a: int, b: bool &default = T, c: vector of string &variadic &default = vector("cool", "beans"))
    {
    print "bar_func", a, b, c;
    }

### events

global foo_event: event(a: vector of any &variadic);

event foo_event(a: vector of any)
    {
    print "foo_event", a;
    }

event bar_event(a: int, b: bool &default = T, c: vector of string &variadic &default = vector("cool", "beans"))
    {
    print "bar_event", a, b, c;
    }

### hooks

global foo_hook: hook(a: vector of any &variadic);

hook foo_hook(a: vector of any)
    {
    print "foo_hook", a;
    }

hook bar_hook(a: int, b: bool &default = T, c: vector of string &variadic &default = vector("cool", "beans"))
    {
    print "bar_hook", a, b, c;
    }

event zeek_init()
    {
### lambdas
    local a = 101;
    local foo_lambda = function[a](b: vector of any &variadic)
        { print "foo_lambda", a, b; };
    local bar_lambda = function[a](b: bool &default = T, c: vector of string &variadic &default = vector("cool", "beans"))
        { print "bar_lambda", a, b, c; };

    foo_func();
    foo_func("test", -1, F);
    bar_func(1);
    bar_func(1, T);
    bar_func(1, T, "test", "baz");

    event foo_event();
    event foo_event("test", -1, F);
    event bar_event(1);
    event bar_event(1, T);
    event bar_event(1, T, "test", "baz");

    hook foo_hook();
    hook foo_hook("test", -1, F);
    hook bar_hook(1);
    hook bar_hook(1, T);
    hook bar_hook(1, T, "test", "baz");

    foo_lambda();
    foo_lambda("test", -1, F);
    bar_lambda();
    bar_lambda(T);
    bar_lambda(T, "test", "baz");
    }
