# @TEST-DOC: Demo how a builtin function can be installed without using bifcl. See the load-so-bif/src/Plugin.cc::InitPreScript() that's executed right during @load time.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/plugin-load-so-bif/* .
# @TEST-EXEC: (./configure --zeek-dist=${DIST} && VERBOSE=1 make) >&2
#
# Take the shared library and copy it as demo.so file into mypackage,
# regardless of what the acutal platform (dynlib on OSX) would use.
# @TEST-EXEC: cp ./build/lib/Demo-Foo* ./mypackage/demo.so
# @TEST-EXEC: zeek -b test.zeek >out
# @TEST-EXEC: btest-diff out

# @TEST-START-FILE ./mypackage/__load__.zeek

module LoadSo;
export {
	## Function installed when loading demo.so, return the input.
	global call_me: function(x: count): count;
}

# Loading the shared object file populated LoadSo::call_me() with a BuiltinFunc FuncVal.
@load ./demo.so
# @TEST-END-FILE

# @TEST-START-FILE test.zeek
@load ./mypackage

event zeek_init()
	{
	print "Calling LoadSo::call_me(42)";
	local r = LoadSo::call_me(42);
	print fmt("got back: %s", r);
	}
# @TEST-END-FILE test.zeek
