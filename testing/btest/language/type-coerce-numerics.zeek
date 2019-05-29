# @TEST-EXEC: zeek -b first_set.zeek >first_set.out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff first_set.out
# @TEST-EXEC-FAIL: zeek -b double_convert_failure1.zeek >double_convert_failure1.out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure1.out
# @TEST-EXEC-FAIL: zeek -b double_convert_failure2.zeek >double_convert_failure2.out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff double_convert_failure2.out

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
	}

# The following cases should throw errors.
event zeek_init()
	{
	# Throw an error for trying to coerce negative values to unsigned
	local negative = myrecord($cc = -5);
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