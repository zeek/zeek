# @TEST-EXEC: bro -b %INPUT >out
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
	
	case type bool as b, addr as a:
		print "Bool or address!", a;
		break;
	default:
		print "Somethign else!";
		break;
	}
	}

event bro_init()
	{
	switch_one("My StrIng");
	switch_one(42);
	switch_one(1.2.3.4);
	}
