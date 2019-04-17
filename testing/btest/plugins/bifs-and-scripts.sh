# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -NN Demo::Foo >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro Demo/Foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo =-= >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo =-= >>output
# @TEST-EXEC-FAIL: BRO_PLUGIN_PATH=`pwd` bro -b Demo/Foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b ./activate.zeek -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b ./activate.zeek  Demo/Foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b Demo::Foo  Demo/Foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

mkdir -p scripts/Demo/Foo/base/

cat >scripts/__load__.zeek <<EOF
@load ./Demo/Foo/base/at-startup.zeek
EOF

cat >scripts/Demo/Foo/__load__.zeek <<EOF
@load ./manually.zeek
EOF

cat >scripts/Demo/Foo/manually.zeek <<EOF
event bro_init() &priority=-10
        {
        print "plugin: manually loaded";
        print "calling bif", hello_plugin_world();
        }
EOF

cat >scripts/Demo/Foo/base/at-startup.zeek <<EOF
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

cat >activate.zeek <<EOF
@load-plugin Demo::Foo
EOF

