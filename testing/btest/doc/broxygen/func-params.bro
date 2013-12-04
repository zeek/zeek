# @TEST-EXEC: bro -b -X broxygen.config %INPUT
# @TEST-EXEC: btest-diff autogen-reST-func-params.rst

@TEST-START-FILE broxygen.config
identifier	test_func_params*	autogen-reST-func-params.rst
@TEST-END-FILE

## This is a global function declaration.
##
## i: First param.
## j: Second param.
##
## Returns: A string.
global test_func_params_func: function(i: int, j: int): string;

type test_func_params_rec: record {
	## This is a record field function.
	##
	## i: First param.
	## j: Second param.
	##
	## Returns: A string.
	field_func: function(i: int, j: int): string;
};
