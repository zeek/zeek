# @TEST-DOC: Verify rejection of certain metadata types.
#
# @TEST-EXEC: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module App;

export {
	redef enum EventMetadata::ID += {
		MY_METADATA = 1000,
		MY_TABLE = 1002,
		MY_VECTOR = 1003,
	};
}

type R: record {
	f: file;
	a: any;
	l: function(x: count): bool;
};

event zeek_init()
	{
	assert ! EventMetadata::register(MY_METADATA, any);
	assert ! EventMetadata::register(MY_METADATA, table[count] of any);
	assert ! EventMetadata::register(MY_METADATA, table[count] of function(x: count): bool);
	assert ! EventMetadata::register(MY_METADATA, R);
	assert ! EventMetadata::register(MY_METADATA, vector of R);
	}
