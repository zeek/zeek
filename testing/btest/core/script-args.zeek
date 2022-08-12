# Don't run for C++ scripts, since script invocation of Zeek hashes
# the script differently, leading to complaints that there are no scripts.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: printf '#!' > test.zeek
# @TEST-EXEC: printf "$BUILD/src/zeek -b --\n" >> test.zeek
# @TEST-EXEC: cat %INPUT >> test.zeek
# @TEST-EXEC: chmod u+x test.zeek

# @TEST-EXEC: zeek -b -- %INPUT -a -b -c >out
# @TEST-EXEC: $(dirname %INPUT)/test.zeek -d -e -f >>out

# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print zeek_script_args;
	}
