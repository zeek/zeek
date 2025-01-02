# @TEST-DOC: ZAM maintenance script for validating synthesized operations.
#
# We don't check the output, since it varies for benign reasons as ZAM
# operations are modified. What matters is the exit status of success.
# @TEST-EXEC: zeek -b -O validate-ZAM %INPUT
