#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test(la1: double, lo1: double, la2: double, lo2: double)
	{
	print fmt("%.4e", haversine_distance(la1, lo1, la2, lo2));
	}

event zeek_init()
	{
	# Test two arbitrary locations.
	test(37.866798, -122.253601, 48.25, 11.65);
	# Swap the order of locations to verify the distance doesn't change.
	test(48.25, 11.65, 37.866798, -122.253601);

	# Distance of one second of latitude (crossing the equator).
	test(.0001388889, 0, -.0001388889, 0);

	# Distance of one second of longitude (crossing the prime meridian).
	test(38, 0.000138999, 38, -0.000138999);

	# Distance of one minute of longitude (test extreme longitude values).
	test(38, 180, 38, -179.98333);

	# Two locations on opposite ends of the Earth.
	test(45, -90, -45, 90);
	# Same, but verify that extreme latitude values work.
	test(90, 0, -90, 0);
	}
