# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type r1: record {
	a: count;
	b: double;
	c: string;
};

type r2: record {
	a: count;
	b1: double &default = 1.0;
	b2: double &default = 2.0;
	c: string &optional;
	d: string &optional;
};

event zeek_init()
	{
	print "bool", value_footprint(T, F);
	print "bool", value_footprint(T, T);
	print "count", value_footprint(3, F);
	print "count", value_footprint(4, T);
	print "int", value_footprint(-3, F);
	print "int", value_footprint(-4, T);
	print "double", value_footprint(-3.0, F);
	print "double", value_footprint(4e99, T);
	print "string", value_footprint("short", F);
	print "string", value_footprint("longlonglong", T);
	print "pattern", value_footprint(/short/, F);
	print "pattern", value_footprint(/longlonglong/, T);
	print "addr", value_footprint(1.2.3.4, F);
	print "addr", value_footprint([ffff::ffff], T);
	print "subnet", value_footprint(1.2.3.4/22, F);
	print "subnet", value_footprint([ffff::ffff]/99, T);
	print "port", value_footprint(123/tcp, F);
	print "port", value_footprint(9999/udp, T);

	local l1: r1;
	print "l1", value_footprint(l1, F);
	print "l1", value_footprint(l1, T);

	local l1b = r1($a=3, $b=3.0, $c="3");
	print "l1b", value_footprint(l1b, F);
	print "l1b", value_footprint(l1b, T);

	local l2: r2;
	print "l2", value_footprint(l2, F);
	print "l2", value_footprint(l2, T);

	local l2b = r2($a=3, $b1=99.0, $c="I'm here");
	print "l2b", value_footprint(l2b, F);
	print "l2b", value_footprint(l2b, T);

	local v1 = vector(9, 7, 3, 1);
	print "v1", value_footprint(v1, F);
	print "v1", value_footprint(v1, T);

	local v2 = vector(v1, v1);
	print "v2", value_footprint(v2, F);
	print "v2", value_footprint(v2, T);

	local v3 = vector(l1, l1b);
	print "v3", value_footprint(v3, F);
	print "v3", value_footprint(v3, T);

	local t1 = table([1] = 1, [2] = 4, [3] = 9);
	print "t1", value_footprint(t1, F);
	# Note, table and set footprint values using count_entries=T because
	# table indices are ListVal's, so those add their own container
	# entry counts into the sum.
	print "t1", value_footprint(t1, T);

	local t2 = table([1, 3] = 1, [2, 3] = 4, [3, 3] = 9);
	print "t2", value_footprint(t2, F);
	print "t2", value_footprint(t2, T);

	local t3 = table([1, 3] = v2, [2, 3] = v2);
	print "t3", value_footprint(t3, F);
	print "t3", value_footprint(t3, T);

	local t4 = table([1, 3] = l1, [2, 3] = l1b);
	print "t4", value_footprint(t4, F);
	print "t4", value_footprint(t4, T);

	local s1 = set(1, 4, 9);
	print "s1", value_footprint(s1, F);
	print "s1", value_footprint(s1, T);

	local s2 = set([1, 3], [2, 3], [3, 3]);
	print "s2", value_footprint(s2, F);
	print "s2", value_footprint(s2, T);

	local s3: set[r1, count];
	add s3[l1b, 9];
	add s3[l1b, 12];
	print "s3", value_footprint(s3, F);
	print "s3", value_footprint(s3, T);

	local s4 = set(vector(l1b), vector(l1b), vector(l1b));
	print "s4", value_footprint(s4, F);
	print "s4", value_footprint(s4, T);
	}
