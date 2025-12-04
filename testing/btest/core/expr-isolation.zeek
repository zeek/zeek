# @TEST-DOC: Expressions that fail to evaluate in isolation should fail silently, rather than potentially crashing (regression) due to null pointer de-ref's.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

function fmt_addr(a : addr): string
	{
	return fmt(is_v6_addr(a) ? "<%s>" : "%s", a);
	}

event zeek_init()
	{
	print fmt_addr([E::F]);
	}
