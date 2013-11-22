# @TEST-EXEC: bro -X broxygen.config %INPUT
# @TEST-EXEC: btest-diff example.rst

@TEST-START-FILE broxygen.config
script	example.rst	broxygen/example.bro
@TEST-END-FILE

@load broxygen/example.bro
