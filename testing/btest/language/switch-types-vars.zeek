# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function switch_one(v: any)
	{
	switch (v) {
	case type string as s:
		print "string!", s;
		break;
	
	case type count as c:
		print "count!", c;
		break;

	case type int:
		print "int!";
		break;

	case type double, type port:
		print "double or port";
		break;

	case type bool as b, type addr as a:
		print "Bool or address?";

		if ( v is bool )
			print "    bool", b;

		if ( v is addr )
			print "    addr", a;

		break;
	default:
		print "Something else!";
		break;
	}
	}

event zeek_init()
	{
	switch_one("My StrIng");
	switch_one(42);
	switch_one(1.2.3.4);
	switch_one(T);
	switch_one(-13);
	switch_one(42/udp);
	switch_one(3.1415926);
	}
