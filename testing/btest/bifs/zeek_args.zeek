# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap -e 'print zeek_args()' | sed -E 's#^\[[^,]*[/\\]zeek(\.exe)?#[zeek#' >out
# @TEST-EXEC: btest-diff-remove-abspath out
