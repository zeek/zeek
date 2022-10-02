# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

### functions

global foo_func: function(a: string &default="hello", b: vector of string &variadic);
global bar_func: function(a: string &default="hello", b: vector of string &variadic &default = vector("cool", "beans"));

# &defaults and &variadic transfer from the declaration automatically
function foo_func(a: string, b: vector of string)
    {
    print "foo_func", a, b;
    }

function bar_func(a: string, b: vector of string)
    {
    print "bar_func", a, b;
    }

### events

global foo_event: event(a: string &default="hello", b: vector of string &variadic);
global bar_event: event(a: string &default="hello", b: vector of string &variadic &default = vector("cool", "beans"));

event foo_event(a: string, b: vector of string)
    {
    print "foo_event", a, b;
    }

event bar_event(a: string, b: vector of string)
    {
    print "bar_event", a, b;
    }

### hooks

global foo_hook: hook(a: string &default="hello", b: vector of string &variadic);
global bar_hook: hook(a: string &default="hello", b: vector of string &variadic &default = vector("cool", "beans"));

hook foo_hook(a: string, b: vector of string)
    {
    print "foo_hook", a, b;
    }

hook bar_hook(a: string, b: vector of string)
    {
    print "bar_hook", a, b;
    }

event zeek_init()
    {
    foo_func();
    bar_func();

    event foo_event();
    event bar_event();

    hook foo_hook();
    hook bar_hook();
    }
