# @TEST-DOC: Regression test for incorrect reuse of temporaries when inlining
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type R: record {
	field1: count;
};

global yes = T;

function pred(my_R: R): bool
	{
	# In the following, my_R$field1 will never be evaluated ...
	if ( yes || my_R$field1 == 4 )
		return T;
	else
		return F;
	}

event zeek_init()
	{
	local my_R = R($field1=3);

	# ... prior to the regression, the third argument in this print
	# was taken from the temporary in pred() that *would* have held
	# my_R$field1 had that ever been evaluated, but instead it holds
	# the default ZVal value of 0.
	print pred(my_R), my_R, my_R$field1;
	}
