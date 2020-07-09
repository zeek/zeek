# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

@load base/utils/backtrace

function print_bt(show_args: bool, one_line: bool)
	{
	print "";
	print "--- Backtrace ---";
	print_backtrace(show_args, one_line, "|", 2);
	}

function foo(c: count)
	{
	print_bt(T, F);
	}

function bar(a: string, b: bool)
	{
	print_bt(F, T);
	foo(444);
	}

event zeek_init()
	{
	print_bt(F, F);
	bar("asdf", T);
	}
