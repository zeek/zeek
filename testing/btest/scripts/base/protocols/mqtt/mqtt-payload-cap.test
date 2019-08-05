# @TEST-EXEC: zeek -b -r $TRACES/mqtt.pcap %INPUT >output
# @TEST-EXEC: btest-diff mqtt_publish.log

redef MQTT::max_payload_size = 8;

@load policy/protocols/mqtt
