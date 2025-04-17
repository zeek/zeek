# @TEST-DOC: Regression test for Zeekygen with identifiers that Zeek establishes in-core, not via scripts.
#
# This used to segfault (see GH-3718) due to unprotected access to the
# declaring_script member in Zeekygen's IdentifierInfo class. The staleness
# check also requires an existing output file, newer than Zeek itself, to
# progress sufficiently into Zeekygen's Manager::IsUpToDate().
#
# @TEST-EXEC: touch test.rst
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b -X zeekygen.config %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff test.rst

# @TEST-START-FILE zeekygen.config
identifier	Log::WRITER_ASCII	test.rst
# @TEST-END-FILE
