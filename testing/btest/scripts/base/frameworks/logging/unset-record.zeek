#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff testing.log

redef enum Log::ID += { TESTING };

type Foo: record {
	val1: count;
	val2: count;
} &log;

type Bar: record {
	a: Foo   &log &optional;
	b: count &log;
};

event zeek_init()
{
    Log::create_stream(TESTING, [$columns=Bar]);

    local x: Bar;

    x = [$b=6];
    Log::write(TESTING, x);

    x = [$a=[$val1=1,$val2=2], $b=3];
    Log::write(TESTING, x);
}
