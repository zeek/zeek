# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin Demo Foo
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -NN Demo::Foo >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro demo/foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo =-= >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo =-= >>output
# @TEST-EXEC-FAIL: BRO_PLUGIN_PATH=`pwd` bro -b demo/foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b ./activate.bro -r $TRACES/empty.trace >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b ./activate.bro  demo/foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -b Demo::Foo  demo/foo -r $TRACES/empty.trace >>output

# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

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
        }
EOF

mkdir -p scripts/demo/foo/base/

cat >scripts/demo/foo/base/at-startup.bro <<EOF
event bro_init() &priority=10
        {
        print "plugin: automatically loaded at startup";
        print "calling bif", hello_plugin_world();
        }
EOF

cat >src/functions.bif <<EOF
function hello_plugin_world%(%): string
        %{
        return new StringVal("Hello from the plugin!");
        %}
EOF

cat >activate.bro <<EOF
@load-plugin Demo::Foo
EOF

cat >src/events.bif <<EOF
event plugin_event%(foo: count%);
EOF
