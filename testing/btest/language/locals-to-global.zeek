# @TEST-DOC: Ensure that locals are not hoisted to global scope.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout

module Test;

export {
	function func1()
		{
		local t: string = "one";
		print t;
		}
	function func2()
		{
		local t: string = "two";
		print t;
		}
}

event zeek_init()
	{
	func1();
	func2();
	}
