# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing NoPatchVersion
# @TEST-EXEC: cp -r %DIR/plugin-nopatchversion-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -N Testing::NoPatchVersion >> output
# @TEST-EXEC: btest-diff output
