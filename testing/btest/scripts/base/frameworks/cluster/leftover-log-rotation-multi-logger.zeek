# @TEST-DOC: Ensure that left-over log rotation tags the logger name on as well.

# @TEST-EXEC: echo ".log" >> .shadow.conn.log
# @TEST-EXEC: echo "" >> .shadow.conn.log
# @TEST-EXEC: echo "leftover conn log" > conn.log

# @TEST-EXEC: echo ".log" >> .shadow.dns.log
# @TEST-EXEC: echo "" >> .shadow.dns.log
# @TEST-EXEC: echo "leftover dns log" > dns.log

# Start Zeek as cluster node logger-2.
# @TEST-EXEC: CLUSTER_NODE=logger-2 zeek -b %INPUT > out

# Ensure leftover files were removed.
# @TEST-EXEC: ! test -f .shadow.conn.log
# @TEST-EXEC: ! test -f conn.log
# @TEST-EXEC: ! test -f .shadow.dns.log
# @TEST-EXEC: ! test -f dns.log

# Ensure the rotated files end-up in the default log-queue directory and have
# the logger-2 name encoded into them.
# @TEST-EXEC: ls ./log-queue/conn__*.log >>out
# @TEST-EXEC: ls ./log-queue/dns__*.log >>out
# @TEST-EXEC: cat ./log-queue/conn__*logger-2__.log ./log-queue/dns__*logger-2__.log >>out

# @TEST-EXEC: TEST_DIFF_CANONIFIER='sed -r "s/[0-9]{2}/XX/g"'  btest-diff out

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
        ["logger-1"] = [$node_type=Cluster::LOGGER,  $ip=127.0.0.1, $p=1234/tcp],
        ["logger-2"] = [$node_type=Cluster::LOGGER,  $ip=127.0.0.1, $p=1235/tcp],
};
@TEST-END-FILE

# Switch settings into a supervisor/non-zeekctl setup
redef Log::default_rotation_dir = "log-queue";
redef Log::rotation_format_func = archiver_rotation_format_func;
redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_postprocessor_cmd = "";

event zeek_init()
	{
	terminate();
	}
