# The ASAN leak detection complains (correctly!) about this script
# leaking memory due to the script-level cycles it includes as
# stress-tests, so just disable leak checking.
# @TEST-EXEC: ASAN_OPTIONS="$ASAN_OPTIONS,detect_leaks=0" zeek -b %INPUT >out
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

# For testing mutually recursive records.
type X: record {
};

type Y: record {
    x: X;
};

redef record X += {
    y: Y &optional;
};

event zeek_init()
	{
	print "bool", val_footprint(T);
	print "count", val_footprint(4);
	print "int", val_footprint(-4);
	print "double", val_footprint(4e99);
	print "string", val_footprint("longlonglong");
	print "pattern", val_footprint(/longlonglong/);
	print "addr", val_footprint([ffff::ffff]);
	print "subnet", val_footprint([ffff::ffff]/99);
	print "port", val_footprint(9999/udp);

	local l1: r1;
	print "l1", val_footprint(l1);

	local l1b = r1($a=3, $b=3.0, $c="3");
	print "l1b", val_footprint(l1b);

	local l2: r2;
	print "l2", val_footprint(l2);

	local l2b = r2($a=3, $b1=99.0, $c="I'm here");
	print "l2b", val_footprint(l2b);

	local v1 = vector(9, 7, 3, 1);
	print "v1", val_footprint(v1);

	local v2 = vector(v1, v1);
	print "v2", val_footprint(v2);

	local v3 = vector(l1, l1b);
	print "v3", val_footprint(v3);

	local t1 = table([1] = 1, [2] = 4, [3] = 9);
	# Note, table and set footprint values using count_entries=T because
	# table indices are ListVal's, so those add their own container
	# entry counts into the sum.
	print "t1", val_footprint(t1);

	local t2 = table([1, 3] = 1, [2, 3] = 4, [3, 3] = 9);
	print "t2", val_footprint(t2);

	local t3 = table([1, 3] = v2, [2, 3] = v2);
	print "t3", val_footprint(t3);

	local t4 = table([1, 3] = l1, [2, 3] = l1b);
	print "t4", val_footprint(t4);

	local s1 = set(1, 4, 9);
	print "s1", val_footprint(s1);

	local s2 = set([1, 3], [2, 3], [3, 3]);
	print "s2", val_footprint(s2);

	local s3: set[r1, count];
	add s3[l1b, 9];
	add s3[l1b, 12];
	print "s3", val_footprint(s3);

	local s4 = set(vector(l1b), vector(l1b), vector(l1b));
	print "s4", val_footprint(s4);

	local x: X;
	local y: Y;

	x$y = y;
	y$x = x;

	print val_footprint(x);
	print val_footprint(y);

	local self_ref_table: table[string] of any;
	print "srt", val_footprint(self_ref_table);
	self_ref_table["x"] = self_ref_table;
	print "srt", val_footprint(self_ref_table);
	}
