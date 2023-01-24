# Tests the keyboard_layout code in the RDP protocol for handling
# keyboards script-layer doesn't know about, and the fallback
# to looking for best guesses.

# @TEST-EXEC: zeek -C -b -r $TRACES/rdp/rdp-unknown-keyboard.pcap %INPUT
# @TEST-EXEC: btest-diff rdp.log

@load base/protocols/rdp