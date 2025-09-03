# @TEST-DOC: Regression test for lambda construction that used to violate memory safety
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# It just needs to run without crashing. It generates a bunch of warnings but
# those aren't of interest here.
# @TEST-EXEC: zeek -b -O ZAM %INPUT

function g()
	{
	}

function gen0(f: function())
	{
	function[f]()
		{
		print f;
		};
	}

function genN(c: count)
	{
	switch c
		{
		case 0: gen0(g); break;
		case 1: gen0(g); break;
		case 2: gen0(g); break;
		case 3: gen0(g); break;
		case 4: gen0(g); break;
		}
	}

event zeek_init()
	{
	genN(3);
	}
