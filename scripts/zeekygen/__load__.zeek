@load test-all-policy.zeek

# Scripts which are commented out in test-all-policy.zeek.
@load frameworks/conn_key/vlan_fivetuple.zeek

@load protocols/ssl/decryption.zeek
@ifdef ( Cluster::CLUSTER_BACKEND_ZEROMQ )
@load frameworks/cluster/backend/zeromq/connect.zeek
@endif
@load frameworks/cluster/nodes-experimental/manager.zeek
@load frameworks/cluster/websocket/server.zeek
@load frameworks/control/controllee.zeek
@load frameworks/control/controller.zeek

@load frameworks/management/agent/main.zeek
@load frameworks/management/controller/main.zeek
@load frameworks/management/node/__load__.zeek
@load frameworks/management/node/main.zeek
@load frameworks/files/extract-all-files.zeek
@load frameworks/signatures/iso-9660.zeek
@load policy/misc/dump-events.zeek
@load policy/misc/systemd-generator.zeek
@load policy/protocols/conn/speculative-service.zeek
@load policy/protocols/dns/disable-opcode-log-fields.zeek

@if ( have_spicy() )
# Loading this messes up documentation of some elements defined elsewhere.
# @load frameworks/spicy/record-spicy-batch.zeek
@load frameworks/spicy/resource-usage.zeek
@endif

@load ./example.zeek
