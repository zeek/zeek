# @TEST-DOC: Check that the Redis analyzer is available.
#
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_SPICY_REDIS'
