# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MyVec: vector of count;

# global, type deduction, named ctor
global gdn = MyVec("zero"); # type clash in init

# global, type explicit, named ctor
global gen: MyVec = MyVec("one"); # type clash in init

# global, type deduction, anon ctor
global gda = vector("two"); # fine
global gda2 = MyVec(2); # fine
event zeek_init()
	{
	gda = gda2; # type clash
	}

# global, type explicit, anon ctor
global gea: MyVec = vector("three"); # type clash

# local, type deduction, named ctor
event zeek_init()
    {
    local ldn = MyVec("thousand"); # type clash
    }

# local, type explicit, named ctor
event zeek_init()
    {
    local len: MyVec = MyVec("thousand-one"); # type clash
    }

# local, type deduction, anon ctor
event zeek_init()
    {
    local lda = vector("thousand-two");   # fine
    lda = MyVec("thousand-two");    # type clash
    }

# local, type explicit, anon ctor
event zeek_init()
    {
    local lea: MyVec = vector("thousand-three"); # type clash
    }
