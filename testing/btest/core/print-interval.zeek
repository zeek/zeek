# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function mult10k(p: interval, n: interval, i: count &default=0)
	{
	if ( i == 4 )
		return;

	print p;
	print n;
	mult10k(p * 10000, n * 10000, i + 1);
	}

local d = 0.12345678912345 usecs;
local nd = -d;
print 0sec;
mult10k(d, nd);

d = 1.001 usec;
print d;
print d * 1000;

print 1.1usec * 10000;

print 8.5 days;
print 7.5 hrs;
print 6.5 mins;
print 5.5 secs;
print 4.5 msecs;
print 3.5 usecs;

print 2 days + 2 secs;
