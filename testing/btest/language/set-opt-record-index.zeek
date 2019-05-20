# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

# Make sure a set can be indexed with a record that has optional fields

type FOO: record {
        a: count;
        b: count &optional;
};

event zeek_init()
        {
        local set_of_foo: set[FOO] = set();

        local f: FOO;
        f$a = 1;

        add set_of_foo[f];
        add set_of_foo[[$a=3]];

        local f3: FOO; # = [$a=4, $b=5];
        f3$a = 4;
        f3$b = 5;

        add set_of_foo[f3];

        add set_of_foo[[$a=4, $b=5]];

        print set_of_foo;

        print "";

        for ( i in set_of_foo )
            print i;

        print "";

        local f2: FOO;
        f2$a = 2;

        print f in set_of_foo;
        print f2 in set_of_foo;

        print "";

        f3$a = 4;
        print f3 in set_of_foo;

        f3$b = 4;
        print f3 in set_of_foo;

        f3$b = 5;
        print f3 in set_of_foo;

        }
