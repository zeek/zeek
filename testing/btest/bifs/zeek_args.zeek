# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace -e 'print zeek_args()' | sed -E 's#^\[[^,]*[/\\]zeek(\.exe)?#[zeek#' >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
