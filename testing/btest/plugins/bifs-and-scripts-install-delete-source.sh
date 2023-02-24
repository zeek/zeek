# @TEST-DOC: Create a plugin, build it, copy its tgz file, delete the source tree, install via the tgz. This ensures the tgz is self-contained and does not have anything pointing back to the source.
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u the-plugin Demo Foo
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: cd ./the-plugin && ./configure --zeek-dist=${DIST} --install-root=`pwd`/test-install && make
# @TEST-EXEC: cp -H ./the-plugin/build/Demo_Foo.tgz .
# @TEST-EXEC: rm -rf ./the-plugin
# @TEST-EXEC: ${DIST}/cmake/zeek-plugin-install-package.sh Demo_Foo `pwd`/test-install
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd`/test-install zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo "===" >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd`/test-install zeek -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo "===" >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd`/test-install zeek Demo/Foo -r $TRACES/empty.trace >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

mkdir -p the-plugin/scripts/Demo/Foo/base/

cat >the-plugin/scripts/__load__.zeek <<EOF
@load ./Demo/Foo/base/at-startup.zeek
EOF

cat >the-plugin/scripts/Demo/Foo/__load__.zeek <<EOF
@load ./manually.zeek
EOF

cat >the-plugin/scripts/Demo/Foo/manually.zeek <<EOF
event zeek_init() &priority=-10
        {
        print "plugin: manually loaded";
        print "calling bif", hello_plugin_world();
        }
EOF

cat >the-plugin/scripts/Demo/Foo/base/at-startup.zeek <<EOF
event zeek_init() &priority=10
        {
        print "plugin: automatically loaded at startup";
        }
EOF

cat >the-plugin/src/foo.bif <<EOF
function hello_plugin_world%(%): string
        %{
        return zeek::make_intrusive<zeek::StringVal>("Hello from the plugin!");
        %}

event plugin_event%(foo: count%);
EOF
