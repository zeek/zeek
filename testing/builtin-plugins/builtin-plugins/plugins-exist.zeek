# @TEST-DOC: Assumes below plugins have been built into Zeek. This test runs during the include_plugins_debian11_task (see .cirrus.yml).

# @TEST-EXEC: zeek -N Corelight::CommunityID >>out
# @TEST-EXEC: zeek -N Seiso::Kafka >>out
# @TEST-EXEC: zeek -N mitrecnd::HTTP2 >>out
# @TEST-EXEC: zeek -N ICSNPP::BACnet >>out
# @TEST-EXEC: btest-diff out
