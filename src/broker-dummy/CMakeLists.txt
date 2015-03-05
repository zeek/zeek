# Placeholder for Broker-based communication functionality, not enabled
# by default.  This helps satisfy coverage unit tests pass regardless of
# whether Broker is enabled or not.

include(BroSubdir)

bif_target(comm.bif)
bif_target(data.bif)
bif_target(messaging.bif)
bif_target(store.bif)

bro_add_subdir_library(broker_dummy ${BIF_OUTPUT_CC})
add_dependencies(bro_broker_dummy generate_outputs)
