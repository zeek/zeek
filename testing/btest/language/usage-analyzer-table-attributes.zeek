# @TEST-DOC: Usage analyzer marked lambdas and functions in attribute expressions of unused tables or record types as unused. That is a bit confusing. Regression test for #3122.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module MyModule;

## Lambda on table.
const ids1: table[count] of string = {
        [1] = "One",
} &default=function(c: count): string {
	return fmt("unknown-%d", c);
};


## External default function
function default_id(c: count): string {
	return fmt("unknown-%d", c);
}

const ids2: table[count] of string = {
        [1] = "One",
} &default=default_id;


## &default expression using function
function default_id2(): string {
	return "";
}

const ids3: table[count] of string = {
        [1] = "One",
} &default=default_id2() + "";


## &expire_func lambda using another function
function expire_f(t: table[count] of string, c: count): interval {
	return 0.0sec;
}

const ids4: table[count] of string = {
        [1] = "One",
} &expire_func=function(t: table[count] of string, c: count): interval {
	return expire_f(t, c);
};
