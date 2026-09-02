# Analyzer for MQTT Protocol (currently v3.1.1, no v5.0 support)

%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/mqtt/MQTT.h"
	#include "zeek/analyzer/protocol/mqtt/consts.bif.h"
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

	%member{
		uint64_t subscription_topic_count_;
	%}

	%init{
		subscription_topic_count_ = 0;
	%}

	function reset_subscription_topic_count(): bool
		%{
		subscription_topic_count_ = 0;
		return true;
		%}

	function subscription_topic_limit_reached(): bool
		%{
		++subscription_topic_count_;
		return zeek::BifConst::MQTT::max_topics_per_subscription > 0 &&
		       subscription_topic_count_ >= zeek::BifConst::MQTT::max_topics_per_subscription;
		%}
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
