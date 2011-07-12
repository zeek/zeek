# A basic test of the known-hosts script's logging and asset_tracking options

# @TEST-EXEC: bro -r $TRACES/wikipedia.trace %INPUT KnownHosts::asset_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-local.log
# @TEST-EXEC: btest-diff knownhosts-local.log

# @TEST-EXEC: bro -r $TRACES/wikipedia.trace %INPUT KnownHosts::asset_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-remote.log
# @TEST-EXEC: btest-diff knownhosts-remote.log

# @TEST-EXEC: bro -r $TRACES/wikipedia.trace %INPUT KnownHosts::asset_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-all.log
# @TEST-EXEC: btest-diff knownhosts-all.log

# @TEST-EXEC: bro -r $TRACES/wikipedia.trace %INPUT KnownHosts::asset_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_hosts.log

@load protocols/conn

redef Site::local_nets += {141.142.0.0/16};
