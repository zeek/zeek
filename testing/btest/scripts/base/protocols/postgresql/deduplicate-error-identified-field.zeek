# @TEST-DOC: Test weird for duplicated identified fields in a ErrorRespone message.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zcat < $TRACES/postgresql/postgresql-error-field-memory-exhaustion.pcap.gz | zeek -b -r - %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m postgresql.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/postgresql
