# @TEST-DOC: Very basic registration of event metadata identifiers.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

module App;

export {
	redef enum EventMetadata::ID += {
		MY_STRING = 1000,
		MY_COUNT = 1001,
		MY_TABLE = 1002,
	};
}

event zeek_init()
	{
	assert EventMetadata::register(MY_STRING, string);
	assert EventMetadata::register(MY_STRING, string); # double register is okay
	assert EventMetadata::register(MY_COUNT, count);
	assert EventMetadata::register(MY_COUNT, count);
	assert EventMetadata::register(MY_TABLE, table[string] of count);
	assert EventMetadata::register(MY_TABLE, table[string] of count);

	# Type mismatch all return F, but no output on stderr.
	assert ! EventMetadata::register(MY_STRING, count);
	assert ! EventMetadata::register(MY_COUNT, string);
	assert ! EventMetadata::register(MY_TABLE, table[count] of string);
	}
