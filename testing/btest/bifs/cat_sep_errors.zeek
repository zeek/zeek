# @TEST-DOC: Runtime errors calling cat_sep()
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr
event zeek_init()
	{
	print cat_sep();
	}

# @TEST-START-NEXT
event zeek_init()
	{
	print cat_sep("sep");
	}

# @TEST-START-NEXT
# bad types 1
event zeek_init()
	{
	print cat_sep("sep", 1);
	}

# @TEST-START-NEXT
# bad types 2
event zeek_init()
	{
	print cat_sep(1, "default");
	}

# @TEST-START-NEXT
event zeek_init()
	{
	print cat_sep([$a=1], "default");
	}
