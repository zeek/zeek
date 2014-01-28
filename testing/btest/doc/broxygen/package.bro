# @TEST-EXEC: bro -b -X broxygen.config %INPUT
# @TEST-EXEC: btest-diff test.rst

@TEST-START-FILE broxygen.config
package	broxygen	test.rst
@TEST-END-FILE

@load broxygen
