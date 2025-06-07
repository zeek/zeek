# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: spicyz -d -o foo.hlto foo.spicy foo.evt
# @TEST-EXEC: zeek -r ${TRACES}/http/post.trace Zeek::Spicy foo.hlto %INPUT >>output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: This test validates that hooks from EVT files are invoked after hooks in the Spicy grammar.

redef Spicy::enable_print = T;

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_FOO, 80/tcp);
	}

event foo_last(x: foo::X)
	{
	print "Zeek: lowest prio", x;
	}

event foo(x: foo::X)
	{
	print "Zeek: default prio", x;
	}

event foo_first(x: foo::X)
	{
	print "Zeek: highest prio", x;
	}

# @TEST-START-FILE foo.spicy
module foo;

public type X = unit {
    x: bytes &size=1;

    on %done priority=-5000 {
        self.x = b"lowest";
        print "Spicy: lowest prio";
    }

    # Default Spicy hook priority is 0.
    on %done {
        self.x = b"default";
        print "Spicy: default prio";
    }

    on %done priority=5000 {
        self.x = b"highest";
        print "Spicy: highest prio";
    }
};

# @TEST-END-FILE

# @TEST-START-FILE foo.evt

# @TEST-START-FILE foo.evt
protocol analyzer Foo over TCP:
    parse originator with foo::X;

# Default EVT hook priority is -1000, but this hook will only execute after the
# Spicy hooks since it needs to go through Zeek's event loop (we might schedule
# immediately, but execution happens later). We can observe what state it saw
# by examining the data though which above Spicy hooks mutate; we expect to see
# data from the default priority handler since we should run right after it.
on foo::X -> event foo(self);
on foo::X -> event foo_first(self) &priority=-500;
on foo::X -> event foo_last(self) &priority=-1500;

export foo::X;
# @TEST-END-FILE
