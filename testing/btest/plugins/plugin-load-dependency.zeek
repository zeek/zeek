# @TEST-EXEC: mkdir 1
# @TEST-EXEC: cd 1 && ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing Plugin1
# @TEST-EXEC: cp -r %DIR/plugin-load-dependency/1 .
# @TEST-EXEC: cd 1 && ./configure --zeek-dist=${DIST} && make

# @TEST-EXEC: mkdir 2
# @TEST-EXEC: cd 2 && ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing Plugin2
# @TEST-EXEC: cp -r %DIR/plugin-load-dependency/2 .
# @TEST-EXEC: cd 2 && ./configure --zeek-dist=${DIST} && make

# @TEST-EXEC: mkdir 3
# @TEST-EXEC: cd 3 && ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing Plugin3
# @TEST-EXEC: cp -r %DIR/plugin-load-dependency/3 .
# @TEST-EXEC: cd 3 && ./configure --zeek-dist=${DIST} && make

# The following run will only work if Zeek loads plugin2 before plugin3 (which
# by alphabetical loading will be the case)
# @TEST-EXEC: ZEEK_PLUGIN_PATH=. zeek -b -N Testing::Plugin3 Testing::Plugin2 | grep -v Zeek:: | sort >> output
#
# @TEST-EXEC: echo >>output
#
# The following run will only work if Zeek loads plugin2 before plugin1 (which
# by alphabetical loading will not be the case).
# @TEST-EXEC: ZEEK_PLUGIN_PATH=. zeek -b -N Testing::Plugin1 Testing::Plugin2 | grep -v Zeek:: | sort >> output
#
# @TEST-EXEC: echo >>output
#
# Finally, try it with self-discovery of all three plugins too.
# @TEST-EXEC: ZEEK_PLUGIN_PATH=. zeek -N | grep -v Zeek:: | sort >> output
#
# @TEST-EXEC: btest-diff output
