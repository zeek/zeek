# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MyTable: table[port] of count;

# global, type deduction, named ctor
global gdn = MyTable(["zero"] = 0); # type clash in init

# global, type explicit, named ctor
global gen: MyTable = MyTable(["one"] = 1); # type clash in init

# global, type deduction, anon ctor
global gda = table(["two"] = 2); # fine
global gda2 = MyTable([2/tcp] = 2); # fine
event zeek_init()
	{
	gda = gda2; # type clash
	}

# global, type explicit, anon ctor
global gea: MyTable = table(["three"] = 3); # type clash

# local, type deduction, named ctor
event zeek_init()
    {
    local ldn = MyTable(["thousand"] = 1000); # type clash
    }

# local, type explicit, named ctor
event zeek_init()
    {
    local len: MyTable = MyTable(["thousand-one"] = 1001); # type clash
    }

# local, type deduction, anon ctor
event zeek_init()
    {
    local lda = table(["thousand-two"] = 1002);   # fine
    lda = MyTable(["thousand-two"] = 1002);    # type clash
    }

# local, type explicit, anon ctor
event zeek_init()
    {
    local lea: MyTable = table(["thousand-three"] = 1003); # type clash
    }
