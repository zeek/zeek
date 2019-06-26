# @TEST-EXEC: zeek -b valid.zeek >valid.out
# @TEST-EXEC: btest-diff valid.out
# @TEST-EXEC-FAIL: zeek -b invalid.zeek > invalid.out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff invalid.out

# hook functions must be called using the "hook" keyword as an operator...

@TEST-START-FILE valid.zeek
hook myhook(i: count)
    {
    print "myhook()", i;
	if ( i == 0 ) break;
    }

hook myhook(i: count) &priority=-1
    {
    print "other myhook()", i;
	}

function indirect(): hook(i: count)
    {
    print "indirect()";
    return myhook;
    }

function really_indirect(): function(): hook(i: count)
    {
    print "really_indirect()";
    return indirect;
    }

global t: table[count] of hook(i: count) = {
    [0] = myhook,
};

event zeek_init()
	{
	hook myhook(3);
	print hook myhook(3);
	print hook myhook(0);
	print "-----------";
	hook indirect()(3);
	print hook indirect()(3);
	print "-----------";
	hook really_indirect()()(3);
	print hook really_indirect()()(3);
	print "-----------";
	local h = t[0];
	hook h(3);
	print hook h(3);
	if ( hook h(3) )
		print "yes";
	if ( ! hook h(0) )
		print "double yes";
	print "-----------";
	hook t[0](3);
	print hook t[0](3);
	}

@TEST-END-FILE

@TEST-START-FILE invalid.zeek
hook myhook(i: count)
	{
	print "myhook()", i;
	if ( i == 0 ) break;
	}

event zeek_init()
	{
	myhook(3);
	print myhook(3);
	print myhook(0);
	hook 2+2;
	print hook 2+2;
	local h = myhook;
	h(3);
	if ( h(3) )
		print "hmm";
	print "done";
	}
@TEST-END-FILE
