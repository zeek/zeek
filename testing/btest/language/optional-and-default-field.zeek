# @TEST-DOC: Warn on record fields that have both, &optional and &default
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

type R: record { };

type X: record {
        c: count &optional &default=5;
        i: int &default=-5 &optional;
        v: vector of string &optional &default=vector();
        r0: R &optional &default=R();
        r1: R &default=R() &optional;
};

global x = X();
print x;
