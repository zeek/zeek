# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Testing NoPatchVersion
# @TEST-EXEC: cp -r %DIR/plugin-nopatchversion-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=$(pwd) zeek -N Testing::NoPatchVersion >> output
# @TEST-EXEC: btest-diff output
