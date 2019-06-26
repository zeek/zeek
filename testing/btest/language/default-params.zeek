# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

### functions

global foo_func: function(a: string &default="hello");

# &defaults transfer from the declaration automatically
function foo_func(a: string)
    {
    print "foo_func", a;
    }

function bar_func(a: string, b: string &default="hi", c: count &default=5)
    {
    print "bar_func", a, b, c;
    }

### events

global foo_event: event(a: string &default="hello");

event foo_event(a: string)
    {
    print "foo_event", a;
    }

event bar_event(a: string, b: string &default="hi", c: count &default=5)
    {
    print "bar_event", a, b, c;
    }

### hooks

global foo_hook: hook(a: string &default="hello");

hook foo_hook(a: string)
    {
    print "foo_hook", a;
    }

hook bar_hook(a: string, b: string &default="hi", c: count &default=5)
    {
    print "bar_hook", a, b, c;
    }

{}

foo_func("test");
foo_func();
bar_func("hmm");
bar_func("cool", "beans");
bar_func("cool", "beans", 13);

event foo_event("test");
event foo_event();
event bar_event("hmm");
event bar_event("cool", "beans");
event bar_event("cool", "beans", 13);

hook foo_hook("test");
hook foo_hook();
hook bar_hook("hmm");
hook bar_hook("cool", "beans");
hook bar_hook("cool", "beans", 13);
