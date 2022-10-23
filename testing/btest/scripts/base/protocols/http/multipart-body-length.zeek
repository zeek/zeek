# @TEST-EXEC: zeek -C -r $TRACES/http/multipart-form-data.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

# This test is mainly checking the request_body_len field for correctness.
# Historical versions of Zeek would mistakenly count the body-lengths of the
# multipart sub-entities twice: once upon the end of the sub-entity and then
# again upon the end of the top-level entity that contains all sub-entities.
# The size of just the top-level entity is the correct one to use.
