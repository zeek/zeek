# @TEST-EXEC-FAIL: zeek -b %INPUT >&2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	# Do not allow local variables with ::prefix.
	local ::a = 1;
	}

@TEST-START-NEXT

# Do not allow :: prefix for an identifier containing a module.
hook ::Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count) { }

@TEST-START-NEXT
# Do not allow exporting names with ::
module MyModule;

export {
	global ::c = 1;
	global ::h: hook();
}

@TEST-START-NEXT
# Do not allow :: prefix on parameter names.
function f(::a: string) { }

@TEST-START-NEXT
# Non-existing global identifier.
event zeek_init()
	{
	print ::missing;
	}

@TEST-START-NEXT

module MyModule;

function ::f() {
}

event zeek_init()
	{
	MyModule::f();
	}
