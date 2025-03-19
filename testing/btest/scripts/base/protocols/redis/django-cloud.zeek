# @TEST-DOC: Test Redis traffic from a django app using Redis (in the cloud) as a cache
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/django-cloud.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# This test has a bunch of factorial commands, try to test for the correct
# factorial without exploding the baseline

@load base/protocols/redis

redef Redis::ports += {
	10625/tcp,
};

global largest_num: count = 0;
global largest_result: string = "";
global num_sets: count = 0;

event Redis::set_command(c: connection, command: Redis::SetCommand)
	{
	local factorial_of = to_count(command$key[13:]);
	if ( factorial_of > largest_num )
		{
		largest_num = factorial_of;
		largest_result = command$value[:];
		}

	num_sets += 1;
	}

event zeek_done()
	{
	print fmt("Factorial of %d is %s", largest_num, largest_result);
	print fmt("Found %d SET commands", num_sets);
	}
