# @TEST-DOC: Test that limits on MQTT topic counts and subscriptions/unsubscriptions function correctly.
#
# @TEST-EXEC: zeek -b -r $TRACES/mqtt-subscribe-pending-topics.pcapng %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff-cut -m mqtt_connect.log

@load base/frameworks/notice/weird
@load base/protocols/mqtt

redef MQTT::max_topics_per_subscription = 5;
redef MQTT::max_pending_subscriptions = 5;
