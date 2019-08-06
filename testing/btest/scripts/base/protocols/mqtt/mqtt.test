# @TEST-EXEC: zeek -b -r $TRACES/mqtt.pcap %INPUT >output
# @TEST-EXEC: btest-diff mqtt_connect.log
# @TEST-EXEC: btest-diff mqtt_subscribe.log
# @TEST-EXEC: btest-diff mqtt_publish.log

@load policy/protocols/mqtt
