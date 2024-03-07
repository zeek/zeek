# @TEST-DOC: Zeek does not have a script land void type, but internally it does exist (indexing a set, or a function returning no result). Regression test #3640.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# identifier void not defined...
global x: void = 1;

# @TEST-START-NEXT
type R: record {
	x: void;
};


# @TEST-START-NEXT
function x(): void {
	return "a";
};

# @TEST-START-NEXT
function x() {
	return "a";
};

# @TEST-START-NEXT

global x = set(3.4.5.6, 9.8.7.6);
print |x|;
print |x[3.4.5.6]|;

# @TEST-START-NEXT
local x = set(5, 3);
local y: any = x[3];
print y;

# @TEST-START-NEXT
function x() {
	print "x()";
}

global z: any = x();
print x();
print |x()|;
