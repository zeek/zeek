# A basic test of the known-hosts script's logging and asset_tracking options

# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT Known::host_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-local.log
# @TEST-EXEC: btest-diff knownhosts-local.log

# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT Known::host_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-remote.log
# @TEST-EXEC: btest-diff knownhosts-remote.log

# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT Known::host_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-all.log
# @TEST-EXEC: btest-diff knownhosts-all.log

# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT Known::host_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_hosts.log

@load protocols/conn/known-hosts

redef Site::local_nets += {141.142.0.0/16};
