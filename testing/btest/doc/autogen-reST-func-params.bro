# @TEST-EXEC: bro --doc-scripts %INPUT
# @TEST-EXEC: btest-diff autogen-reST-func-params.rst

## This is a global function declaration.
##
## i: First param.
## j: Second param.
##
## Returns: A string.
global test_func: function(i: int, j: int): string;

type test_rec: record {
	## This is a record field function.
	##
	## i: First param.
	## j: Second param.
	##
	## Returns: A string.
	field_func: function(i: int, j: int): string;
};
