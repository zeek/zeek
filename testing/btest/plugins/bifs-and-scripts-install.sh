# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: ./configure --bro-dist=${DIST} --install-root=`pwd`/test-install
# @TEST-EXEC: make
# @TEST-EXEC: make install
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd`/test-install bro -NN Demo::Foo >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd`/test-install bro demo/foo -r $TRACES/empty.trace >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

mkdir -p scripts/demo/foo/base/

cat >scripts/__load__.bro <<EOF
@load ./demo/foo/base/at-startup.bro
EOF

cat >scripts/demo/foo/__load__.bro <<EOF
@load ./manually.bro
EOF

cat >scripts/demo/foo/manually.bro <<EOF
event bro_init() &priority=-10
        {
        print "plugin: manually loaded";
        print "calling bif", hello_plugin_world();
        }
EOF

cat >scripts/demo/foo/base/at-startup.bro <<EOF
event bro_init() &priority=10
        {
        print "plugin: automatically loaded at startup";
        }
EOF

cat >src/foo.bif <<EOF
function hello_plugin_world%(%): string
        %{
        return new StringVal("Hello from the plugin!");
        %}

event plugin_event%(foo: count%);
EOF

cat >activate.bro <<EOF
@load-plugin Demo::Foo
EOF

