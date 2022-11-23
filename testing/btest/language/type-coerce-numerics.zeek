# We skip this test for ZAM, because it will optimize away the values
# that are created to induce overflows.  An alternative would be to change
# the test to print those values.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b first_set.zeek >first_set.out 2>first_set.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff first_set.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff first_set.err

# @TEST-EXEC-FAIL: zeek -b double_convert_failure1.zeek >double_convert_failure1.out 2>double_convert_failure1.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure1.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure1.err

# @TEST-EXEC-FAIL: zeek -b double_convert_failure2.zeek >double_convert_failure2.out 2>double_convert_failure2.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure2.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure2.err

# @TEST-EXEC-FAIL: zeek -b int_convert_failure.zeek >int_convert_failure.out 2>int_convert_failure.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff int_convert_failure.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff int_convert_failure.err

# @TEST-EXEC: zeek -b vectors.zeek >vectors.out 2>vectors.err
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff vectors.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff vectors.err

@TEST-START-FILE first_set.zeek
type myrecord : record {
	ii: int &optional;
	cc: count &optional;
	dd: double &optional;
};

# Allow coercion from count values to int
global globalint: myrecord &redef;
redef globalint = [$ii = 2];

# All of these cases should succeed
event zeek_init()
	{
	# Allow coercion from count values to int
	local intconvert1 = myrecord($ii = 3);
	print(intconvert1$ii);
	print(type_name(intconvert1$ii));

	local intconvert2: myrecord = record($ii = 4);
	print(intconvert2$ii);
	print(type_name(intconvert2$ii));

	local intconvert3: myrecord = [$ii = 5];
	print(intconvert3$ii);
	print(type_name(intconvert3$ii));

	local intconvert4: myrecord;
	intconvert4$ii = 6;
	print(intconvert4$ii);
	print(type_name(intconvert4$ii));

	# Convert from count/integer values into doubles
	local doubleconvert1 = myrecord($dd = 7);
	print(doubleconvert1$dd);
	print(type_name(doubleconvert1$dd));

	local doubleconvert2 = myrecord($dd = -5);
	print(doubleconvert2$dd);
	print(type_name(doubleconvert2$dd));

	local cnt = 5;
	cnt += +2;
	print cnt;
	print type_name(cnt);
	cnt -= -3;
	print cnt;
	print type_name(cnt);
	}

event zeek_init()
	{
	# This value is INT64_MAX+1, which overflows a signed integer and
	# throws an error
	local overflow = myrecord($ii = 9223372036854775808);
	}
@TEST-END-FILE

@TEST-START-FILE double_convert_failure1.zeek
type myrecord : record {
	cc: count &optional;
};

event zeek_init()
	{
	local convert = myrecord($cc = 5.0);
	}
@TEST-END-FILE

@TEST-START-FILE double_convert_failure2.zeek
type myrecord : record {
	cc: count &optional;
};

event zeek_init()
	{
	local convert = myrecord($cc = -5.0);
	}
@TEST-END-FILE

@TEST-START-FILE int_convert_failure.zeek
type myrecord : record {
	cc: count &optional;
};

event zeek_init()
	{
	local convert = myrecord($cc = -5);
	}
@TEST-END-FILE

@TEST-START-FILE vectors.zeek
event zeek_init()
	{
	local c1 : vector of count = { 1 , 2 };
	local c2 : vector of count = { 3 , 4 };
	local c3 = c1 + c2;
	print type_name(c1);
	print type_name(c2);
	print type_name(c3);
	print c1;
	print c2;
	print c3;

	local i1 : vector of int = { 1, 2 };
	local i2 : vector of int = { 3, 4 };
	local i3 = i1 + i2;
	print type_name(i1);
	print type_name(i2);
	print type_name(i3);
	print i1;
	print i2;
	print i3;

	local d1 : vector of double = { 1, 2 };
	local d2 : vector of double = { 3, 4 };
	local d3 = d1 + d2;
	print type_name(d1);
	print type_name(d2);
	print type_name(d3);
	print d1;
	print d2;
	print d3;
	}
@TEST-END-FILE
