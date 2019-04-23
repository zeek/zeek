# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek -X zeexygen.config %INPUT
# @TEST-EXEC: btest-diff example.rst

@TEST-START-FILE zeexygen.config
script	zeexygen/example.zeek	example.rst
@TEST-END-FILE

@load zeexygen/example
