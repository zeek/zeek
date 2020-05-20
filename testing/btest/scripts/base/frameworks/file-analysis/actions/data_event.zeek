# @TEST-EXEC: zeek -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out

redef test_print_file_data_events = T;
