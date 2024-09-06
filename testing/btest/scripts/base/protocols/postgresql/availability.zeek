# @TEST-DOC: Check that the PostgreSQL analyzer is available.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -NN | grep -qi 'ANALYZER_POSTGRESQL'
