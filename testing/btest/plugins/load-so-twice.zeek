# @TEST-DOC: Same as load-so.zeek, but attempt to load the .so file twice.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/plugin-load-so/* .
# @TEST-EXEC: (./configure --zeek-dist=${DIST} && VERBOSE=1 make) >&2
#
# Take the shared library and copy it as demo.so file into mypackage,
# regardless of what the acutal platform (dynlib on OSX) would use.
# @TEST-EXEC: cp ./build/lib/Demo-Foo* ./mypackage/demo.so
# @TEST-EXEC: zeek -b ./mypackage >out
# @TEST-EXEC: btest-diff out

# @TEST-START-FILE ./mypackage/__load__.zeek
@load ./demo.so
@load ./demo.so

event zeek_init()
	{
	print "Loaded mypackage.so";
	}
# @TEST-END-FILE
