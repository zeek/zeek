# This test verifies that Zeek terminates upon SIGTERM during regular script
# processing.
#
# See the sigterm-stdin.sh test for additional explanation of what's happening.
#
# Use a separate output file since btest-bg-wait replaces .stdout/.stderr:
# @TEST-EXEC: bash %INPUT >output 2>&1

# Helper to return the PID of the Zeek process launched in the background.
zeek_pid() {
    # The btest-bg-run .pid file contains the parent of the Zeek process
    local ppid=$(cat zeek/.pid)
    ps -xo pid,ppid,comm | awk "\$2 == \"$ppid\" && \$3 == \"zeek\" { print \$1 }"
}

cleanup() {
    btest-bg-wait -k 5
}

trap cleanup EXIT

btest-bg-run zeek "zeek exit_only_after_terminate=T"

# Wait until we see Zeek running.
for i in $(seq 10); do
    pid=$(zeek_pid)
    [ -n "$pid" ] && break
    sleep 1
done

if [ -z "$pid" ]; then
    echo "Couldn't determine Zeek PID"
    exit 1
fi

for i in $(seq 10); do
    kill $pid
    [ -z "$(zeek_pid)" ] && break
    sleep 1
done

pid=$(zeek_pid)

if [ -n "$pid" ]; then
    echo "Zeek PID $pid did not shut down"
    exit 1
fi

exit 0
