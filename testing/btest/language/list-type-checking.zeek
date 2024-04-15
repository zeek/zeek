# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MyList: list of count;

# global, type deduction, named ctor
global gdn = MyList("zero"); # type clash in init

# global, type explicit, named ctor
global gen: MyList = MyList("one"); # type clash in init

# global, type deduction, anon ctor
global gda = list("two"); # fine
global gda2 = MyList(2); # fine
event zeek_init()
	{
	gda = gda2; # type clash
	}

# global, type explicit, anon ctor
global gea: MyList = list("three"); # type clash

# local, type deduction, named ctor
event zeek_init()
    {
    local ldn = MyList("thousand"); # type clash
    }

# local, type explicit, named ctor
event zeek_init()
    {
    local len: MyList = MyList("thousand-one"); # type clash
    }

# local, type deduction, anon ctor
event zeek_init()
    {
    local lda = list("thousand-two");   # fine
    lda = MyList("thousand-two");    # type clash
    }

# local, type explicit, anon ctor
event zeek_init()
    {
    local lea: MyList = list("thousand-three"); # type clash
    }
