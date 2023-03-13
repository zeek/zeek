# @TEST-DOC: Run a bit of Python for the kicks, assume there'll be no Python 4 in the near future.
# @TEST-EXEC: zeek %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Python::run_simple_string("import sys; print(\"Python\", sys.version_info.major)");
	Python::run_simple_string("print(sys)");
	}
