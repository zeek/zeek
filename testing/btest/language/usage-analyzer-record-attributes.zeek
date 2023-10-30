# @TEST-DOC: Usage analyzer marked lambdas and functions in attribute expressions of unused tables or record types as unused. That is a bit confusing. Regression test for #3122.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module MyModule;

function gen_id(): string {
	return cat(rand(10000));
}

type R1: record {
	xxx_id: string &default=gen_id();
};

# Seems we can't actually put functions on &default on records, so the
# following uses a directly invoked lambda instead.
type R2: record {
	xxx_id: string &default=(function(): string { return cat(rand(10000)); })();
};
