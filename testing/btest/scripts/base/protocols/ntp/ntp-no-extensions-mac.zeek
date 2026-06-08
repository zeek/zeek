# TODO: this should be fixed in a better way than just throwing a binpac exception, such as
# actually properly parsing the extensions. This solves the problem for right now, but it
# should be considered a bandaid.

# @TEST-DOC: Test that reading an NTP packet with a MAC but no extensions doesn't crash.

# @TEST-EXEC: zeek -b -C -r $TRACES/ntp/ntp-no-extensions-mac.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m analyzer_debug.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ntp
@load frameworks/analyzer/debug-logging
