# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

type MySet: set[port];

# global, type deduction, named ctor
global gdn = MySet(0); # type clash in init

# global, type explicit, named ctor
global gen: MySet = MySet(1); # type clash in init

# global, type deduction, anon ctor
global gda = set(2); # fine
event zeek_init()
	{
	gda = MySet(2);  # type clash in assignment
	}

# global, type explicit, anon ctor
global gea: MySet = set(3); # type clash

# local, type deduction, named ctor
event zeek_init()
    {
    local ldn = MySet(1000); # type clash
    }

# local, type explicit, named ctor
event zeek_init()
    {
    local len: MySet = MySet(1001); # type clash
    }

# local, type deduction, anon ctor
event zeek_init()
    {
    local lda = set(1002);   # fine
    lda = MySet(1002);    # type clash
    }

# local, type explicit, anon ctor
event zeek_init()
    {
    local lea: MySet = set(1003); # type clash
    }

type MyRecord: record {
	user: string;
	host: string;
	host_port: count &default=22;
	path: string;
};

global set_of_records: set[MyRecord];

event zeek_init()
	{
	# Set ctor w/ anonymous record ctor should coerce.
	set_of_records = set([$user="testuser", $host="testhost", $path="testpath"]);
	}
