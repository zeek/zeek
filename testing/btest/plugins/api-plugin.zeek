# @TEST-DOC: A plugin testing some parts Zeek's C++ API
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo API
# @TEST-EXEC: cp -r %DIR/api-plugin/* .
#
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek %INPUT >output
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

module DemoAPI;

export {
	type Severity: enum {
		CRITICAL = 1,
		ERROR = 2,
		WARNING = 3,
		INFO = 4,
	};
}

module User;

redef enum DemoAPI::Severity += {
	USER_DEBUG = 50,
};
