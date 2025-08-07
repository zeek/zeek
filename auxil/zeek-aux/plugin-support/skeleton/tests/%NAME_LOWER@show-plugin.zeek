# @TEST-EXEC: zeek -NN @PLUGIN_NAMESPACE@::@PLUGIN_NAME@ |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
