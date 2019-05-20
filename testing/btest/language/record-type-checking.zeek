# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MyRec: record {
	a: port &default = 1/tcp;
};

# global, type deduction, named ctor
global grdn = MyRec($a = 0); # type clash in init

# global, type explicit, named ctor
global gren: MyRec = MyRec($a = 1); # type clash in init

# global, type deduction, anon ctor
global grda = [$a = 2]; # fine
event zeek_init()
	{
	grda = MyRec($a = 2);  # type clash in assignment
	}

# global, type explicit, anon ctor
global grea: MyRec = [$a = 3]; # type clash

# local, type deduction, named ctor
event zeek_init()
    {
    local lrdn = MyRec($a = 1000); # type clash
    }

# local, type explicit, named ctor
event zeek_init()
    {
    local lren: MyRec = MyRec($a = 1001); # type clash
    }

# local, type deduction, anon ctor
event zeek_init()
    {
    local lrda = [$a = 1002];   # fine
    lrda = MyRec($a = 1002);    # type clash
    }

# local, type explicit, anon ctor
event zeek_init()
    {
    local lrea: MyRec = [$a = 1003]; # type clash
    }
