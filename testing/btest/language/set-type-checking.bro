# @TEST-EXEC-FAIL: bro -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MySet: set[port];

# global, type deduction, named ctor
global gdn = MySet(0); # type clash in init

# global, type explicit, named ctor
global gen: MySet = MySet(1); # type clash in init

# global, type deduction, anon ctor
global gda = set(2); # fine
event bro_init()
	{
	gda = MySet(2);  # type clash in assignment
	}

# global, type explicit, anon ctor
global gea: MySet = set(3); # type clash

# local, type deduction, named ctor
event bro_init()
    {
    local ldn = MySet(1000); # type clash
    }

# local, type explicit, named ctor
event bro_init()
    {
    local len: MySet = MySet(1001); # type clash
    }

# local, type deduction, anon ctor
event bro_init()
    {
    local lda = set(1002);   # fine
    lda = MySet(1002);    # type clash
    }

# local, type explicit, anon ctor
event bro_init()
    {
    local lea: MySet = set(1003); # type clash
    }
