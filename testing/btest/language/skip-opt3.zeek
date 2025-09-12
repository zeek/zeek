# @TEST-EXEC: zeek -b %INPUT --no-opt-file=skip-opt >out 2>&1
# @TEST-EXEC: btest-diff out

function always()
	{
	print "always";
	}

function no_ZAM() &no_ZAM_opt
	{
	print "no ZAM";
	}

function no_CPP() &no_CPP_opt
	{
	print "no CPP";
	}

event zeek_init()
	{
	print always;
	print no_ZAM;
	print no_CPP;
	}
