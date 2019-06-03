# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; unset BRO_DISABLE_BROXYGEN; zeek -X zeekygen.config %INPUT
# @TEST-EXEC: btest-diff example.rst

@TEST-START-FILE zeekygen.config
script	zeekygen/example.zeek	example.rst
@TEST-END-FILE

@load zeekygen/example
