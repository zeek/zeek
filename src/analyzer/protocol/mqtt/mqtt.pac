# Analyzer for MQTT Protocol (currently v3.1.1, no v5.0 support)

%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/mqtt/MQTT.h"
	#include "zeek/analyzer/protocol/mqtt/events.bif.h"
	#include "zeek/analyzer/protocol/mqtt/types.bif.h"
%}

analyzer MQTT withcontext {
	connection: MQTT_Conn;
	flow:       MQTT_Flow;
};

# Our connection consists of two flows, one in each direction.
connection MQTT_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = MQTT_Flow(true);
	downflow = MQTT_Flow(false);
};

%include mqtt-protocol.pac

flow MQTT_Flow(is_orig: bool) {
	#flowunit = MQTT_PDU(is_orig) withcontext(connection, this);
	datagram = MQTT_PDU(is_orig) withcontext(connection, this);
};

%include commands/connect.pac
%include commands/connack.pac
%include commands/publish.pac
%include commands/puback.pac
%include commands/pubrec.pac
%include commands/pubrel.pac
%include commands/pubcomp.pac
%include commands/subscribe.pac
%include commands/suback.pac
%include commands/unsuback.pac
%include commands/unsubscribe.pac
%include commands/disconnect.pac
%include commands/pingreq.pac
%include commands/pingresp.pac
