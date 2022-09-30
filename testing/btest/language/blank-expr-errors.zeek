# @TEST-DOC: Do not allow to reference the blank identifier.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
event zeek_init()
	{
	local vec = vector( "1", "2", "3" );
	for ( _, v in vec )
		print _;
	}

@TEST-START-NEXT
event zeek_init()
	{
	local _ = vector( "1", "2", "3" );
	print _;
	}

@TEST-START-NEXT
# Ensure it does not work in a module, either.
module MyModule;
event zeek_init()
	{
	local _ = vector( "1", "2", "3" );
	print _;
	}

@TEST-START-NEXT
# Ensure _ can not referenced when it's a const in an export section.
# Adding the const _ isn't an error though.
module MyModule;

export {
	const _: count = 1;
}

event zeek_init()
	{
	print MyModule::_;
	}

@TEST-START-NEXT
# Ensure it does not work in a function.
module MyModule;
function helper()
	{
	local _ = vector( "1", "2", "3" );
	print _;
	}

event zeek_init()
	{
	helper();
	}
