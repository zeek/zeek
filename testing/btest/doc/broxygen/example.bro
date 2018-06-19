# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; bro -X broxygen.config %INPUT
# @TEST-EXEC: btest-diff example.rst

@TEST-START-FILE broxygen.config
script	broxygen/example.bro	example.rst
@TEST-END-FILE

@load broxygen/example.bro
