#!/bin/bash
#
# Minimal shell based supervisor.
#
# Relies on bash's SIGINT propagation for shutdown. SIGTERM does not
# work and will orphan the processes.
#
# shellcheck disable=SC2086
set -eu

INTERFACE=${ZEEK_INTERFACE:-lo}
WORKERS=${ZEEK_WORKERS:-4}
PROXIES=${ZEEK_PROXIES:-2}
LOGGERS=${ZEEK_LOGGERS:-1}
SPOOL_DIR=${ZEEK_SPOOL_DIR:-$(pwd)/spool}

# Disable log rotation by default, so the logs within the logger's
# working directory just grow and grow. Good for testing and avoids
# spilling archive-log messages...
ARGS=${ZEEK_ARGS:-local Log::default_rotation_interval=0sec}

# Ignore checksum errors by default here.
WORKER_ARGS=${ZEEK_WORKER_ARGS:--C}

# The cluster backend script appended to all Zeek invocations.
CLUSTER_BACKEND_ARGS=${ZEEK_CLUSTER_BACKEND_ARGS:-policy/frameworks/cluster/backend/zeromq}

# spawn_process <name> <args...>
#
# Creates the working directory and launches a Zeek process in
# the background the given cluster name, passing args to it.
function spawn_process {
    local name=$1
    shift # make "$@" in the sub shell work

    local wdir=$SPOOL_DIR/$name
    mkdir -p $wdir
    cp $SPOOL_DIR/cluster-layout.zeek $wdir/cluster-layout.zeek

    # Spawn a new shell and exec to zeek.
    (
        cd $wdir
        export CLUSTER_NODE=$name
        exec zeek "$@" $CLUSTER_BACKEND_ARGS
    ) &
}

zeek-cluster-layout-generator \
    -L $LOGGERS \
    -P $PROXIES \
    -W $WORKERS -o $SPOOL_DIR/cluster-layout.zeek

# Spawn all the different processes, go go go!
spawn_process manager $ARGS
for i in $(seq 1 $LOGGERS); do spawn_process logger-$i $ARGS; done
for i in $(seq 1 $PROXIES); do spawn_process proxy-$i $ARGS; done
for i in $(seq 1 $WORKERS); do spawn_process worker-$i $WORKER_ARGS -i $INTERFACE $ARGS; done

wait
