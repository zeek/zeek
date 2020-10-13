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
