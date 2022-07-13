# This test verifies that Zeek, while reading stdin to parse scripts, terminates
# upon SIGTERM.
#
# Running Zeek in a way that portably delivers SIGINT (as ctrl-c would do) is
# tricky. With job control done locally in this script, even when run by an
# interactive bash, SIGINT is blocked. When running via btest-bg-run, the
# backgrounded processes have their SIGINT and SIGQUIT blocked, per POSIX:
# https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html
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

# Launch Zeek so it stalls, reading from stdin.
mkfifo input
btest-bg-run zeek "cat ../input | zeek"

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

# Now try several times to terminate the process via SIGTERM. We try repeatedly
# because we might hit Zeek in a brief window in time where the signal is
# blocked -- it gets unblocked during the parsing stage, since this enables
# ctrl-c to work during interactive input.
#
# Terminating Zeek does not terminate the "cat", since the latter would only
# notice upon a data write that the pipe is gone. We leave it to btest-bg-wait
# to clean up at exit.
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
