# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT >out
# @TEST-EXEC: btest-diff out

redef test_print_file_data_events = T;
