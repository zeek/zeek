# @TEST-DOC: ZAM maintenance script for validating synthesized operations.
#
# @TEST-EXEC: zeek -b -O validate-ZAM %INPUT >output
# @TEST-EXEC: btest-diff output
